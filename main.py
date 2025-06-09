import time
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os
import requests
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

# 설정
CLOUDFRONT_DOMAIN = os.environ.get('CLOUDFRONT_DOMAIN')
CLOUDFRONT_KEY_PAIR_ID = os.environ.get('CLOUDFRONT_KEY_PAIR_ID')
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME')
PRIVATE_KEY_PATH = "./private_key.pem"  # .pem 파일 경로
S3_OBJECT_KEY = "uploads/sample_file.txt"  # S3 객체 키 (CloudFront에서 쓰는 경로)

# AWS 자격 증명 설정 (환경 변수 또는 AWS 구성 파일에서 로드됨)
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY 환경 변수 설정 필요

def generate_signed_url_cloudfront(key: str, key_pair_id: str, private_key_path: str, domain: str, expiration_seconds: int = 3600) -> str:
    # 만료 시간 (Unix timestamp)
    expires = int(time.time() + expiration_seconds)

    # 전체 URL
    url = f"https://{domain}/{key}"

    # 정책 생성
    policy = {
        "Statement": [{
            "Resource": url,
            "Condition": {
                "DateLessThan": {"AWS:EpochTime": expires}
            }
        }]
    }
    policy_json = json.dumps(policy, separators=(",", ":"))

    # 개인 키 로드 (PKCS8 또는 PKCS1 둘 다 지원 가능)
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # 서명 생성
    signature = private_key.sign(
        policy_json.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA1()
    )

    # 서명 및 정책 Base64 인코딩 후 CloudFront용 변형
    def cf_safe_b64encode(value: bytes) -> str:
        return base64.b64encode(value).decode("utf-8")\
            .replace("+", "-")\
            .replace("=", "_")\
            .replace("/", "~")

    signed_url = (
        f"{url}"
        f"?Expires={expires}"
        f"&Signature={cf_safe_b64encode(signature)}"
        f"&Key-Pair-Id={key_pair_id}"
    )
    return signed_url

def check_cloudfront():
    signed_url = generate_signed_url_cloudfront(
        key=S3_OBJECT_KEY,
        key_pair_id=CLOUDFRONT_KEY_PAIR_ID,
        private_key_path=PRIVATE_KEY_PATH,
        domain=CLOUDFRONT_DOMAIN,
        expiration_seconds=300
    )

    print(f"서명 URL:\n{signed_url}\n")

    try:
        response = requests.get(signed_url)
        if response.status_code == 200:
            print("✅ 성공: CloudFront 통해 객체에 접근 가능")
        elif response.status_code == 403:
            print("🚫 실패: 권한 오류 (403)")
        elif response.status_code == 404:
            print("❌ 실패: 객체 없음 (404)")
        else:
            print(f"⚠️ 예외 상태 코드: {response.status_code}")
    except Exception as e:
        print(f"❌ 요청 중 오류 발생: {e}")

def check_aws_credentials():
    """
    AWS 자격 증명이 올바르게 설정되어 있는지 확인합니다.
    
    Returns:
        bool: 자격 증명이 설정되어 있으면 True, 아니면 False
    """
    # 환경 변수에서 자격 증명 확인
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    
    if not aws_access_key or not aws_secret_key:
        print("⚠️ 경고: AWS 자격 증명이 환경 변수에 설정되어 있지 않습니다.")
        print("다음 환경 변수를 설정해야 합니다:")
        print("  - AWS_ACCESS_KEY_ID")
        print("  - AWS_SECRET_ACCESS_KEY")
        
        # AWS 자격 증명 파일 확인
        home_dir = os.path.expanduser("~")
        credentials_path = os.path.join(home_dir, ".aws", "credentials")
        
        if os.path.exists(credentials_path):
            print(f"✅ AWS 자격 증명 파일이 존재합니다: {credentials_path}")
            print("   파일이 올바르게 구성되어 있는지 확인하세요.")
            return True
        else:
            print(f"❌ AWS 자격 증명 파일이 없습니다: {credentials_path}")
            print("AWS 자격 증명을 설정하려면 다음 중 하나를 수행하세요:")
            print("1. 환경 변수 설정:")
            print("   Windows: set AWS_ACCESS_KEY_ID=your_access_key")
            print("            set AWS_SECRET_ACCESS_KEY=your_secret_key")
            print("   Linux/Mac: export AWS_ACCESS_KEY_ID=your_access_key")
            print("               export AWS_SECRET_ACCESS_KEY=your_secret_key")
            print("2. AWS 자격 증명 파일 생성:")
            print("   ~/.aws/credentials 파일 생성 후 다음 내용 추가:")
            print("   [default]")
            print("   aws_access_key_id = your_access_key")
            print("   aws_secret_access_key = your_secret_key")
            return False
    
    print("✅ AWS 자격 증명이 환경 변수에 설정되어 있습니다.")
    return True

def upload_to_s3(file_path: str, object_key: str = None):
    """
    S3에 파일을 업로드하고 CloudFront URL을 반환합니다.
    
    Args:
        file_path: 업로드할 로컬 파일 경로
        object_key: S3에 저장될 객체 키 (지정하지 않으면 파일명 사용)
        
    Returns:
        CloudFront 서명된 URL
    """
    if object_key is None:
        object_key = os.path.basename(file_path)
    
    # S3 클라이언트 생성
    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
        region_name=os.environ.get('AWS_S3_REGION_NAME')
    )
    
    try:
        # 파일 업로드
        print(f"파일 '{file_path}'을(를) S3 버킷 '{S3_BUCKET_NAME}'에 업로드 중...")
        s3_client.upload_file(file_path, S3_BUCKET_NAME, object_key)
        print(f"✅ 업로드 성공: {object_key}")
        
        # CloudFront 서명된 URL 생성
        cloudfront_url = generate_signed_url_cloudfront(
            key=object_key,
            key_pair_id=CLOUDFRONT_KEY_PAIR_ID,
            private_key_path=PRIVATE_KEY_PATH,
            domain=CLOUDFRONT_DOMAIN,
            expiration_seconds=3600
        )
        
        print(f"CloudFront 서명된 URL:\n{cloudfront_url}")
        return cloudfront_url
        
    except ClientError as e:
        print(f"❌ 업로드 실패: {e}")
        return None

def create_sample_file_and_upload():
    """
    샘플 텍스트 파일을 생성하고 S3에 업로드한 후 CloudFront URL을 반환합니다.
    """
    # AWS 자격 증명 확인
    if not check_aws_credentials():
        print("❌ AWS 자격 증명이 설정되지 않아 업로드를 건너뜁니다.")
        return None
    
    # 샘플 파일 생성
    sample_file_path = "sample_file.txt"
    with open(sample_file_path, "w") as f:
        f.write("이것은 CloudFront를 통해 업로드된 테스트 파일입니다.\n")
        f.write(f"생성 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"샘플 파일 생성됨: {sample_file_path}")
    
    # 파일 업로드 및 URL 생성
    object_key = f"uploads/{os.path.basename(sample_file_path)}"
    cloudfront_url = upload_to_s3(sample_file_path, object_key)
    
    # 샘플 파일 정리 (선택적)
    # os.remove(sample_file_path)
    
    return cloudfront_url

if __name__ == "__main__":
    # 다운로드 예제 실행    
    print("\n=== CloudFront를 통한 S3 업로드 테스트 ===")
    create_sample_file_and_upload()
    
    print("=== CloudFront 서명된 URL을 통한 다운로드 테스트 ===")
    check_cloudfront()
