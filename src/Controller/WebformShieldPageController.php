<?php

namespace Drupal\webform_shield\Controller;

use Drupal\Core\Controller\ControllerBase;

/**
 * Implement Class WebformShieldPageController.
 */
class WebformShieldPageController extends ControllerBase {

  /**
   * The Webform Shield page where robotic form submissions end up.
   *
   * @return array
   *   Return message.
   */
  public function page(): array {
    return [
      '#type' => 'html_tag',
      '#tag' => 'div',
      '#attributes' => [
        'class' => ['webform-shield-message', 'webform-shield-message-error'],
      ],
      '#value' => $this->t('You have reached this page because you submitted a form that required JavaScript to be enabled and human-like interaction on your browser. This protection is in place to prevent automated submissions and spam on forms. Please return to the page that you came from, enable JavaScript on your browser, and interact with the page before attempting to submit the form again.'),
      '#attached' => [
        'library' => ['webform_shield/webform_shield.form'],
      ],
    ];
  }

}