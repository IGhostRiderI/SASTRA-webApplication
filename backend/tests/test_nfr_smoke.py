import io
import os
import time
import zipfile
import asyncio

import httpx
import pytest


BASE_URL = os.environ.get("NFR_BASE_URL", "http://127.0.0.1:8000")
USERNAME = os.environ.get("NFR_TEST_USERNAME", "")
PASSWORD = os.environ.get("NFR_TEST_PASSWORD", "")


@pytest.mark.anyio
async def test_normal_endpoints_under_1_second():
    timeout = httpx.Timeout(5.0)
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=timeout) as client:
        for endpoint in ("/api/health", "/api/catalog"):
            started = time.perf_counter()
            response = await client.get(endpoint)
            elapsed = time.perf_counter() - started
            assert response.status_code == 200
            assert elapsed < 1.0, f"{endpoint} took {elapsed:.3f}s"


@pytest.mark.anyio
async def test_20_concurrent_health_requests_without_failures():
    timeout = httpx.Timeout(5.0)
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=timeout) as client:
        tasks = [client.get("/api/health") for _ in range(20)]
        responses = await asyncio.gather(*tasks)
    assert all(response.status_code == 200 for response in responses)


async def _login(client: httpx.AsyncClient) -> None:
    if not USERNAME or not PASSWORD:
        pytest.skip("Set NFR_TEST_USERNAME and NFR_TEST_PASSWORD to run scan timing tests.")
    response = await client.post(
        "/api/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    if response.status_code != 200:
        pytest.skip("Could not authenticate for scan timing tests.")


@pytest.mark.anyio
async def test_single_snippet_scan_under_5_seconds():
    timeout = httpx.Timeout(15.0)
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=timeout) as client:
        await _login(client)
        started = time.perf_counter()
        response = await client.post(
            "/api/scan",
            data={
                "code": "import os\nos.system(user_input)\n",
                "code_filename": "demo.py",
                "language": "python",
            },
        )
        elapsed = time.perf_counter() - started

    assert response.status_code == 200, response.text
    assert elapsed < 5.0, f"/api/scan single snippet took {elapsed:.3f}s"


@pytest.mark.anyio
async def test_zip_scan_under_30_seconds():
    timeout = httpx.Timeout(40.0)
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=timeout) as client:
        await _login(client)

        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("one.py", "import os\nos.system(user_input)\n")
            archive.writestr("two.py", "import random\nprint(random.random())\n")
        archive_bytes.seek(0)

        started = time.perf_counter()
        response = await client.post(
            "/api/scan",
            files={"file": ("sample.zip", archive_bytes.getvalue(), "application/zip")},
        )
        elapsed = time.perf_counter() - started

    assert response.status_code == 200, response.text
    assert elapsed < 30.0, f"/api/scan zip took {elapsed:.3f}s"
