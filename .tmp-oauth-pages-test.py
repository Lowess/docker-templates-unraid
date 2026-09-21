from pathlib import Path
from playwright.sync_api import sync_playwright


BASE_URL = "http://127.0.0.1:8765"
SCREENSHOT_DIR = Path("/tmp/oauth-legal-pages")
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


def check_page(page, path, title, heading, screenshot_name):
    response = page.goto(f"{BASE_URL}{path}")
    page.wait_for_load_state("networkidle")
    assert response is not None and response.ok, f"{path} returned {response.status if response else 'no response'}"
    assert page.title() == title
    assert page.get_by_role("heading", name=heading, exact=True).is_visible()
    assert page.locator("script").count() == 0
    assert page.locator('meta[name="robots"]').get_attribute("content") == "noindex, nofollow, noarchive"
    page.screenshot(path=str(SCREENSHOT_DIR / screenshot_name), full_page=True)


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    desktop = browser.new_page(viewport={"width": 1440, "height": 1000}, device_scale_factor=1)
    console_errors = []
    failed_requests = []
    desktop.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
    desktop.on("requestfailed", lambda request: failed_requests.append(f"{request.url}: {request.failure}"))

    check_page(desktop, "/", "Private Access Portal", "Access, deliberately limited.", "home-desktop.png")
    assert desktop.get_by_role("link", name="Privacy policy").get_attribute("href") == "privacy/"
    assert desktop.get_by_role("link", name="Terms of service").get_attribute("href") == "terms/"

    check_page(
        desktop,
        "/privacy/",
        "Privacy Policy — Private Access Portal",
        "Privacy policy",
        "privacy-desktop.png",
    )
    check_page(
        desktop,
        "/terms/",
        "Terms of Service — Private Access Portal",
        "Terms of service",
        "terms-desktop.png",
    )

    mobile = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=1)
    check_page(mobile, "/", "Private Access Portal", "Access, deliberately limited.", "home-mobile.png")
    assert mobile.locator("body").evaluate("el => el.scrollWidth <= window.innerWidth")

    assert not console_errors, f"Browser console errors: {console_errors}"
    assert not failed_requests, f"Failed requests: {failed_requests}"
    print("PASS: home, privacy, and terms pages render and navigate correctly")
    print(f"Screenshots: {SCREENSHOT_DIR}")
    browser.close()
