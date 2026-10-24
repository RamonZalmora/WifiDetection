"""Optional end-to-end browser check. Uses an already running local instance.

Run with a Python installation containing Playwright and Chromium:
python tests/browser_smoke.py /path/to/instance.json
No wireless results are mocked or fabricated by this test.
"""
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def main():
    token = json.loads(Path(sys.argv[1]).read_text())['token']
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path='/usr/bin/chromium', headless=True,
                                    args=['--no-sandbox'])
        page = browser.new_page(viewport={'width': 1440, 'height': 1000})
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto('http://127.0.0.1:8765/#token=' + token)
        page.get_by_text('No experiments', exact=True).wait_for()
        page.locator('nav').get_by_text('WPA2 Recovery Lab', exact=False).click()
        form = page.locator('#generate-form')
        form.locator('[name=name]').fill('Browser laboratory')
        form.locator('[name=ssid]').fill('IEEE')
        form.locator('[name=password]').fill('password')
        form.locator('[name=authorized]').check()
        form.get_by_role('button').click()
        page.wait_for_url('**/#verification')
        test_form = page.locator('#test-form')
        test_form.locator('[name=candidates]').fill('incorrect\npassword')
        test_form.get_by_role('button', name='Start verification').click()
        page.locator('#job-state').get_by_text('VERIFIED MATCH', exact=True).wait_for()
        assert page.locator('#matched-password').inner_text() == 'password'
        assert '2 / 2' in page.locator('#job-metrics').inner_text()
        page.locator('nav').get_by_text('Reports', exact=False).click()
        with page.expect_download() as downloaded:
            page.locator('#report-form').get_by_role('button').click()
        report = Path(downloaded.value.path()).read_text()
        assert '<th>password</th>' not in report
        assert 'VERIFIED MATCH' in report
        page.locator('nav').get_by_text('WiFi Scanner', exact=False).click()
        page.get_by_role('button', name='Scan now', exact=True).click()
        page.get_by_text('Native scanning requires Windows', exact=False).wait_for()
        for route in ['hardware', 'analysis', 'history', 'settings', 'dashboard']:
            page.locator(f'nav a[href="#{route}"]').click()
            assert page.locator('#' + route).is_visible()
        page.screenshot(path='/tmp/wpa2lab-dashboard.png', full_page=True)
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        assert not errors, errors
        browser.close()
    print('Browser smoke passed: project, real MIC verification, report, Linux scan limitation, navigation, responsive layout.')


if __name__ == '__main__':
    main()
