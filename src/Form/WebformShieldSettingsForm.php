<?php

namespace Drupal\webform_shield\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Implement Class Webform Shield Settings Form with enhanced security options.
 */
class WebformShieldSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'webform_shield.settings',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'webform_shield_settings';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('webform_shield.settings');
    
    $form['message'] = [
      '#type' => 'html_tag',
      '#tag' => 'h3',
      '#value' => $this->t('Configuration'),
    ];

    // Form Protection Settings
    $form['form_protection'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Form Protection Settings'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    ];

    $form['form_protection']['form_ids'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Form IDs to Protect'),
      '#default_value' => is_array($config->get('form_ids')) ? implode("\r\n", $config->get('form_ids')) : '',
      '#description' => $this->t('Specify the form IDs that should be protected by Webform Shield. Each form ID should be on a separate line. Wildcard (*) characters can be used.<br><strong>Important:</strong> Protection is OPT-IN based on form IDs, not URL paths. Admin forms (/admin/*) and batch forms (/batch/*) are NOT protected by default and should generally remain unprotected for security and usability reasons.'),
    ];

    $form['form_protection']['excluded_form_ids'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Excluded Form IDs'),
      '#default_value' => implode("\r\n", $config->get('excluded_form_ids') ?? []),
      '#description' => $this->t('Specify the form IDs that should never be protected by Webform Shield, even if they match the inclusion patterns above. Each form ID should be on a separate line. Wildcard (*) characters can be used.<br><strong>Note:</strong> Admin and system forms are excluded by default for safety.'),
    ];

    // Security Settings
    $form['security'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Security Settings'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    ];

    $form['security']['token_timeout'] = [
      '#type' => 'number',
      '#title' => $this->t('Token timeout (seconds)'),
      '#default_value' => $config->get('token_timeout') ?: 900,
      '#min' => 60,
      '#max' => 3600,
      '#step' => 60,
      '#description' => $this->t('How long tokens remain valid before expiring. Default is 900 seconds (15 minutes). Minimum is 60 seconds, maximum is 3600 seconds (1 hour).'),
    ];

    $form['security']['check_ip'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Check IP address'),
      '#default_value' => $config->get('check_ip') !== FALSE,
      '#description' => $this->t('When enabled, tokens will be validated against the client IP address. This provides additional security but may cause issues for users behind proxies or with dynamic IP addresses. Disable if you experience issues with legitimate users.'),
    ];

    $form['security']['rate_limit_enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable rate limiting'),
      '#default_value' => $config->get('rate_limit_enabled') !== FALSE,
      '#description' => $this->t('When enabled, limits the number of token requests per IP address to prevent abuse.'),
    ];

    $form['security']['rate_limit_threshold'] = [
      '#type' => 'number',
      '#title' => $this->t('Rate limit threshold'),
      '#default_value' => $config->get('rate_limit_threshold') ?: 100,
      '#min' => 10,
      '#max' => 1000,
      '#step' => 10,
      '#description' => $this->t('Maximum number of token requests allowed per IP address per hour. Default is 100.'),
      '#states' => [
        'visible' => [
          ':input[name="rate_limit_enabled"]' => ['checked' => TRUE],
        ],
      ],
    ];

    $form['security']['rate_limit_excluded_ips'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Rate Limiting Excluded IPs/Subnets'),
      '#default_value' => implode("\r\n", $config->get('rate_limit_excluded_ips') ?? []),
      '#description' => $this->t('IP addresses and subnets that should be excluded from rate limiting. Each entry should be on a separate line. Supports:<br>• Individual IPs: <code>192.168.1.1</code><br>• IPv4 CIDR subnets: <code>192.168.1.0/24</code><br>• IPv6 addresses: <code>2001:db8::1</code><br>• IPv6 CIDR subnets: <code>2001:db8::/32</code><br><strong>Use case:</strong> Corporate proxy servers, shared NAT gateways, or trusted networks where many legitimate users share the same IP.'),
      '#rows' => 5,
      '#states' => [
        'visible' => [
          ':input[name="rate_limit_enabled"]' => ['checked' => TRUE],
        ],
      ],
    ];

    // Advanced Security Settings
    $form['advanced_security'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Advanced Security Settings'),
      '#collapsible' => TRUE,
      '#collapsed' => TRUE,
    ];

    $form['advanced_security']['log_security_events'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Log security events'),
      '#default_value' => $config->get('log_security_events') !== FALSE,
      '#description' => $this->t('When enabled, security events such as invalid requests, rate limiting, and token validation failures will be logged. This helps with security monitoring but may increase log volume.'),
    ];

    $form['advanced_security']['block_suspicious_requests'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Block suspicious requests'),
      '#default_value' => $config->get('block_suspicious_requests') !== FALSE,
      '#description' => $this->t('When enabled, requests that appear suspicious (missing headers, invalid origins, etc.) will be blocked. This provides enhanced security but may cause issues with some legitimate requests.'),
    ];

    $form['advanced_security']['csrf_token_validation'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Require CSRF tokens'),
      '#default_value' => $config->get('csrf_token_validation') !== FALSE,
      '#description' => $this->t('When enabled, all token requests must include a valid CSRF token. This is strongly recommended for security.'),
      '#disabled' => TRUE, // Always required for security
    ];

    // Development Settings
    $form['development'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Development Settings'),
      '#collapsible' => TRUE,
      '#collapsed' => TRUE,
    ];

    $form['development']['show_form_ids'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Display form IDs'),
      '#default_value' => $config->get('show_form_ids'),
      '#description' => $this->t('When enabled, the form IDs of all forms on every page will be displayed to any user with permission to access these settings. Also displayed will be whether or not Webform Shield is enabled for each form. This should only be turned on temporarily in order to easily determine the form IDs to use.'),
    ];

    $form['development']['debug_mode'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Debug mode'),
      '#default_value' => $config->get('debug_mode'),
      '#description' => $this->t('When enabled, additional debugging information will be logged to watchdog and sent to the browser console. This includes detailed token generation/validation logs, security check results, and step-by-step processing information. <strong>Performance impact:</strong> Should only be enabled during development or temporary troubleshooting. <strong>Security consideration:</strong> Detailed logs may expose system information.'),
    ];

    // Security Status
    $form['security_status'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Security Status'),
      '#collapsible' => TRUE,
      '#collapsed' => TRUE,
    ];

    $form['security_status']['status_info'] = [
      '#type' => 'item',
      '#title' => $this->t('Current Security Level'),
      '#markup' => $this->getSecurityStatusMarkup($config),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    parent::validateForm($form, $form_state);
    
    // Validate excluded IPs format
    $excluded_ips_value = $form_state->getValue('rate_limit_excluded_ips');
    if (!empty($excluded_ips_value)) {
      $excluded_ips = array_filter(explode("\r\n", $excluded_ips_value));
      foreach ($excluded_ips as $line_number => $ip_entry) {
        $ip_entry = trim($ip_entry);
        if (empty($ip_entry)) {
          continue;
        }
        
        // Validate IP format
        if (!$this->validateIpOrSubnet($ip_entry)) {
          $form_state->setErrorByName('rate_limit_excluded_ips', 
            $this->t('Line @line: "@entry" is not a valid IP address or subnet. Use formats like 192.168.1.1, 192.168.1.0/24, or 2001:db8::/32', [
              '@line' => $line_number + 1,
              '@entry' => $ip_entry,
            ])
          );
        }
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    parent::submitForm($form, $form_state);

    $this->config('webform_shield.settings')
      ->set('form_ids', array_filter(explode("\r\n", $form_state->getValue('form_ids'))))
      ->set('excluded_form_ids', array_filter(explode("\r\n", $form_state->getValue('excluded_form_ids'))))
      ->set('token_timeout', (int) $form_state->getValue('token_timeout'))
      ->set('check_ip', (bool) $form_state->getValue('check_ip'))
      ->set('rate_limit_enabled', (bool) $form_state->getValue('rate_limit_enabled'))
      ->set('rate_limit_threshold', (int) $form_state->getValue('rate_limit_threshold'))
      ->set('rate_limit_excluded_ips', array_filter(explode("\r\n", $form_state->getValue('rate_limit_excluded_ips'))))
      ->set('log_security_events', (bool) $form_state->getValue('log_security_events'))
      ->set('block_suspicious_requests', (bool) $form_state->getValue('block_suspicious_requests'))
      ->set('csrf_token_validation', TRUE) // Always enabled for security
      ->set('show_form_ids', (bool) $form_state->getValue('show_form_ids'))
      ->set('debug_mode', (bool) $form_state->getValue('debug_mode'))
      ->save();

    // Clear caches to ensure new settings take effect
    drupal_flush_all_caches();
  }

  /**
   * Validate IP address or subnet format.
   *
   * @param string $ip_entry
   *   The IP address or subnet to validate.
   *
   * @return bool
   *   TRUE if valid, FALSE otherwise.
   */
  private function validateIpOrSubnet($ip_entry) {
    // Check if it's a CIDR subnet
    if (strpos($ip_entry, '/') !== FALSE) {
      $parts = explode('/', $ip_entry);
      if (count($parts) !== 2) {
        return FALSE;
      }
      
      $ip = $parts[0];
      $prefix = $parts[1];
      
      // Validate IP part
      if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return FALSE;
      }
      
      // Validate prefix length
      if (!is_numeric($prefix) || $prefix < 0) {
        return FALSE;
      }
      
      // Check prefix length limits based on IP version
      if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return $prefix <= 32;
      } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return $prefix <= 128;
      }
      
      return FALSE;
    }
    
    // Check if it's a regular IP address
    return filter_var($ip_entry, FILTER_VALIDATE_IP) !== FALSE;
  }

  /**
   * Generate security status markup.
   *
   * @param \Drupal\Core\Config\Config $config
   *   The configuration object.
   *
   * @return string
   *   The security status markup.
   */
  private function getSecurityStatusMarkup($config) {
    $security_features = [
      'CSRF Protection' => TRUE, // Always enabled
      'IP Address Validation' => $config->get('check_ip') !== FALSE,
      'Rate Limiting' => $config->get('rate_limit_enabled') !== FALSE,
      'Security Event Logging' => $config->get('log_security_events') !== FALSE,
      'Suspicious Request Blocking' => $config->get('block_suspicious_requests') !== FALSE,
    ];

    $enabled_count = count(array_filter($security_features));
    $total_count = count($security_features);
    $percentage = round(($enabled_count / $total_count) * 100);

    $markup = '<div class="webform-shield-security-status">';
    $markup .= '<p><strong>Security Level: ' . $percentage . '%</strong> (' . $enabled_count . '/' . $total_count . ' features enabled)</p>';
    $markup .= '<ul>';
    
    foreach ($security_features as $feature => $enabled) {
      $status = $enabled ? '✓ Enabled' : '✗ Disabled';
      $class = $enabled ? 'enabled' : 'disabled';
      $markup .= '<li class="' . $class . '">' . $feature . ': ' . $status . '</li>';
    }
    
    $markup .= '</ul>';
    
    if ($percentage < 80) {
      $markup .= '<p><strong>Recommendation:</strong> Enable more security features for better protection.</p>';
    }
    
    // Add rate limiting exclusion info
    $excluded_ips = $config->get('rate_limit_excluded_ips') ?? [];
    if (!empty($excluded_ips) && $config->get('rate_limit_enabled') !== FALSE) {
      $markup .= '<p><strong>Rate Limiting Exclusions:</strong> ' . count($excluded_ips) . ' IP(s)/subnet(s) excluded</p>';
    }
    
    $markup .= '</div>';
    
    return $markup;
  }

}