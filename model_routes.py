import hashlib
import time
from typing import Dict, List, Optional
from council_contracts import (
    ReceiptEnvelope, RouteAttestationReceipt, ModelQualificationReceipt
)

def create_route_attestation(
    route_id: str,
    provider_name: str,
    endpoint_url: str,
    compliance_tier: str,
    content_retention_days: int = 0,
    zdr_verified: bool = True,
    fallbacks_allowed: bool = False,
    validity_sec: int = 3500
) -> ReceiptEnvelope[RouteAttestationReceipt]:
    """
    Creates and seals an immutable RouteAttestationReceipt strictly satisfying
    all V4.1 verifier constraints:
    - issued_at <= now
    - expires_at > issued_at
    - ttl <= 3600 for private/paid
    - fallbacks_allowed == False for private/paid
    """
    now = time.time()
    account_hash = hashlib.sha256(f"{provider_name}:{endpoint_url}".encode("utf-8")).hexdigest()[:16]
    
    receipt = RouteAttestationReceipt(
        route_id=route_id,
        provider_name=provider_name,
        endpoint_url=endpoint_url,
        account_hash=account_hash,
        compliance_tier=compliance_tier,
        content_retention_days=content_retention_days,
        zdr_verified=zdr_verified,
        fallbacks_allowed=fallbacks_allowed,
        issued_at=now,
        expires_at=now + validity_sec
    )
    return ReceiptEnvelope.seal(receipt)

class RouteRegistry:
    @staticmethod
    def get_standard_routes() -> Dict[str, ReceiptEnvelope[RouteAttestationReceipt]]:
        routes = {}
        
        # 1. Jiunsong Abliterated Local Route (Air-Gapped Localhost)
        r_jiunsong = create_route_attestation(
            route_id="route_jiunsong_supergemma_12b_local",
            provider_name="ollama_local",
            endpoint_url="http://127.0.0.1:11434",
            compliance_tier="LOCAL_ONLY_VERIFIED",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500
        )
        routes[r_jiunsong.payload_sha256] = r_jiunsong
        
        # 2. GLM-5.3 Cyber & Code Route (SiliconFlow)
        r_glm = create_route_attestation(
            route_id="route_glm_5_3_siliconflow",
            provider_name="siliconflow",
            endpoint_url="https://api.siliconflow.cn/v1/chat/completions",
            compliance_tier="HOSTED_NO_TRAIN",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500
        )
        routes[r_glm.payload_sha256] = r_glm
        
        # 3. Qwen-3.8 Frontier Route (SiliconFlow)
        r_qwen = create_route_attestation(
            route_id="route_qwen_3_8_frontier",
            provider_name="siliconflow",
            endpoint_url="https://api.siliconflow.cn/v1/chat/completions",
            compliance_tier="HOSTED_NO_TRAIN",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500
        )
        routes[r_qwen.payload_sha256] = r_qwen

        # 4. DeepSeek-R1 Reasoning Route (SiliconFlow / Local)
        r_r1 = create_route_attestation(
            route_id="route_deepseek_r1_reasoning",
            provider_name="siliconflow",
            endpoint_url="https://api.siliconflow.cn/v1/chat/completions",
            compliance_tier="HOSTED_NO_TRAIN",
            content_retention_days=0,
            zdr_verified=True,
            fallbacks_allowed=False,
            validity_sec=3500
        )
        routes[r_r1.payload_sha256] = r_r1

        # 5. Gemini-3.6-Flash Public 1M Slicer (Google AI Studio)
        r_gemini = create_route_attestation(
            route_id="route_gemini_3_6_flash",
            provider_name="google_ai_studio",
            endpoint_url="https://generativelanguage.googleapis.com/v1beta",
            compliance_tier="PUBLIC_PROVENANCE_ONLY",
            content_retention_days=0,
            zdr_verified=False,
            fallbacks_allowed=False,
            validity_sec=86000
        )
        routes[r_gemini.payload_sha256] = r_gemini

        return routes

if __name__ == "__main__":
    registry = RouteRegistry.get_standard_routes()
    print(f"Generated and sealed {len(registry)} production route attestations:")
    for sha, env in registry.items():
        r = env.payload
        print(f"\n[Route: {r.route_id}]")
        print(f"  - Provider: {r.provider_name} ({r.endpoint_url})")
        print(f"  - Compliance: {r.compliance_tier} | ZDR: {r.zdr_verified} | Fallbacks: {r.fallbacks_allowed}")
        print(f"  - TTL: {r.expires_at - r.issued_at:.0f}s | Payload SHA256: {sha[:16]}...")
