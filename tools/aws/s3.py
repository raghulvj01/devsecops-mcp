from __future__ import annotations

from typing import Any


def check_s3_public_access(region: str = "us-east-1") -> list[dict[str, Any]]:
    """Audit S3 buckets for public access settings.

    Args:
        region: AWS region for the S3 client (default us-east-1).

    Returns:
        List of buckets with their public access block configuration.
    """
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        s3 = boto3.client("s3", region_name=region)
        buckets_resp = s3.list_buckets()
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"AWS S3 error: {exc}") from exc

    results: list[dict[str, Any]] = []
    for bucket in buckets_resp.get("Buckets", []):
        name = bucket["Name"]
        entry: dict[str, Any] = {"bucket": name, "public_access_block": None, "is_potentially_public": False}

        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab.get("PublicAccessBlockConfiguration", {})
            entry["public_access_block"] = {
                "block_public_acls": config.get("BlockPublicAcls", False),
                "ignore_public_acls": config.get("IgnorePublicAcls", False),
                "block_public_policy": config.get("BlockPublicPolicy", False),
                "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
            }
            all_blocked = all(entry["public_access_block"].values())
            entry["is_potentially_public"] = not all_blocked
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                entry["public_access_block"] = "not_configured"
                entry["is_potentially_public"] = True
            elif error_code == "AccessDenied":
                entry["public_access_block"] = "access_denied"
                entry["is_potentially_public"] = "unknown"
            else:
                entry["public_access_block"] = f"error: {error_code}"
                entry["is_potentially_public"] = "unknown"

        results.append(entry)

    return results
