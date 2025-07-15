<?php

namespace Drupal\webform_shield\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Implement Class Webform Shield Settings Form.
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
      '#value' => $this->t('Webform Shield requires that a user has JavaScript enabled and performs human-like interactions to use and submit protected forms.'),
    ];

    $form['form_ids'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Form IDs'),
      '#default_value' => is_array($config->get('form_ids')) ? implode("\r\n", $config->get('form_ids')) : '',
      '#description' => $this->t('Specify the form IDs that should be protected by Webform Shield. Each form ID should be on a separate line. Wildcard (*) characters can be used.'),
    ];

    $form['excluded_form_ids'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Excluded form IDs'),
      '#default_value' => implode("\r\n", $config->get('excluded_form_ids') ?? []),
      '#description' => $this->t('Specify the form IDs that should never be protected by Webform Shield. Each form ID should be on a separate line. Wildcard (*) characters can be used.'),
    ];

    $form['token_timeout'] = [
      '#type' => 'number',
      '#title' => $this->t('Token timeout (seconds)'),
      '#default_value' => $config->get('token_timeout') ?: 900,
      '#min' => 60,
      '#max' => 3600,
      '#step' => 60,
      '#description' => $this->t('How long tokens remain valid before expiring. Default is 900 seconds (15 minutes). Minimum is 60 seconds, maximum is 3600 seconds (1 hour).'),
    ];

    $form['show_form_ids'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Display form IDs'),
      '#default_value' => $config->get('show_form_ids'),
      '#description' => $this->t('When enabled, the form IDs of all forms on every page will be displayed to any user with permission to access these settings. Also displayed will be whether or not Webform Shield is enabled for each form. This should only be turned on temporarily in order to easily determine the form IDs to use.'),
    ];

    return parent::buildForm($form, $form_state);
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
      ->set('show_form_ids', (bool) $form_state->getValue('show_form_ids'))
      ->save();
  }

}