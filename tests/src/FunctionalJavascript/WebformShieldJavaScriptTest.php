<?php

namespace Drupal\Tests\webform_shield\FunctionalJavascript;

use Drupal\FunctionalJavascriptTests\WebDriverTestBase;

/**
 * Tests Webform Shield with JavaScript enabled.
 *
 * @group webform_shield
 */
class WebformShieldJavaScriptTest extends WebDriverTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['webform_shield'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests that forms work after human interaction with AJAX token loading.
   */
  public function testHumanInteractionWithAjaxTokens() {
    $this->drupalGet('/user/password');
    $page = $this->getSession()->getPage();
    $driver = $this->getSession()->getDriver();

    // Verify the form starts in protected state.
    $form = $page->find('css', 'form.webform-shield');
    $this->assertNotNull($form, 'Form has webform-shield class');
    
    // Verify form action is set to blocked page initially.
    $this->assertEquals('/webform-shield', $form->getAttribute('action'));
    
    // Verify token input is empty initially.
    $tokenInput = $page->find('css', 'input[name="webform_shield_token"]');
    $this->assertNotNull($tokenInput, 'Token input field exists');
    $this->assertEquals('', $tokenInput->getValue(), 'Token is initially empty');

    // Fill the name field.
    $name = $this->randomMachineName();
    $page->fillField('Username or email address', $name);

    // Simulate human behavior by moving mouse.
    $driver->mouseOver('//h1[text() = "Reset your password"]');
    
    // Wait for AJAX token request to complete.
    $this->assertSession()->waitForElement('css', 'form.webform-shield-unlocked', 5000);
    
    // Verify form is now unlocked.
    $form = $page->find('css', 'form.webform-shield-unlocked');
    $this->assertNotNull($form, 'Form has been unlocked');
    
    // Verify form action has been restored.
    $originalAction = $form->getAttribute('data-action');
    $this->assertEquals($originalAction, $form->getAttribute('action'), 'Form action restored');
    
    // Verify token has been populated.
    $tokenInput = $page->find('css', 'input[name="webform_shield_token"]');
    $this->assertNotEmpty($tokenInput->getValue(), 'Token has been populated');
    
    // Submit the form.
    $page->pressButton('Submit');

    // Should NOT be on the blocked page - should process the form normally.
    $this->assertSession()->addressNotEquals('/webform-shield');
    
    // Should see the normal form validation message.
    $this->assertSession()->waitForText("{$name} is not recognized as a username or an email address.");
  }

  /**
   * Tests AJAX token endpoint directly.
   */
  public function testTokenEndpoint() {
    // Test with valid form ID.
    $response = $this->drupalGet('/webform-shield/token/user_pass', [
      'external' => FALSE,
      'headers' => [
        'Content-Type' => 'application/json',
        'X-Requested-With' => 'XMLHttpRequest',
      ],
    ], 'POST');
    
    $this->assertSession()->statusCodeEquals(200);
    
    $data = json_decode($this->getSession()->getPage()->getContent(), TRUE);
    $this->assertTrue($data['success'], 'Token generation successful');
    $this->assertNotEmpty($data['token'], 'Token is not empty');
    
    // Test with invalid form ID.
    $this->drupalGet('/webform-shield/token/invalid_form_id', [
      'external' => FALSE,
      'headers' => [
        'Content-Type' => 'application/json',
        'X-Requested-With' => 'XMLHttpRequest',
      ],
    ], 'POST');
    
    $this->assertSession()->statusCodeEquals(400);
  }

  /**
   * Tests that users with skip permission don't get tokens.
   */
  public function testSkipPermission() {
    // Create user with skip permission.
    $user = $this->drupalCreateUser(['skip webform shield']);
    $this->drupalLogin($user);
    
    $this->drupalGet('/user/password');
    $page = $this->getSession()->getPage();
    
    // Form should not have webform-shield class.
    $form = $page->find('css', 'form.webform-shield');
    $this->assertNull($form, 'Form is not protected for users with skip permission');
  }

}