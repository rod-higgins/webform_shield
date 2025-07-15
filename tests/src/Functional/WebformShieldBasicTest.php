<?php

namespace Drupal\Tests\webform_shield\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Tests basic Webform Shield functionality.
 *
 * @group webform_shield
 */
class WebformShieldBasicTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['webform_shield'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests that forms are blocked when JavaScript is disabled.
   *
   * BrowserTestBase tests are non-JavaScript by default, simulating bot behavior.
   */
  public function testFormBlocked() {
    // Try to submit the password reset form (protected by default).
    $this->drupalGet('/user/password');
    $this->submitForm([
      'name' => $this->randomMachineName(),
    ], 'Submit');

    // Should be redirected to the blocked page.
    $this->assertSession()->addressEquals('/webform-shield');
    $this->assertSession()->pageTextContains('Submission failed');
    $this->assertSession()->pageTextContains('human-like interaction');
  }

  /**
   * Tests that configuration form is accessible.
   */
  public function testConfigurationAccess() {
    // Create admin user.
    $admin = $this->drupalCreateUser(['administer webform shield configuration']);
    $this->drupalLogin($admin);

    // Access configuration form.
    $this->drupalGet('/admin/config/user-interface/webform-shield');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->fieldExists('form_ids');
    $this->assertSession()->fieldExists('token_timeout');
  }

}