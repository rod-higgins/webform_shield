<?php

namespace Drupal\webform_shield;

use Drupal\Core\Render\Element\RenderCallbackInterface;

/**
 * Provides a trusted callback to alter Webform Shield form.
 */
class WebformShieldFormAlter implements RenderCallbackInterface {

  /**
   * Callback #pre_render: Alter forms.
   */
  public static function preRender($build) {
    // Add the Webform Shield library.
    $build['#attached']['library'][] = 'webform_shield/webform_shield.form';

    // Store the form ID that the JS can replace the action path along with the
    // form token.
    $form_id = $build['#id'];
    if (isset($build['#attributes']['id'])) {
      $form_id = $build['#attributes']['id'];
    }

    $build['#attached']['drupalSettings']['webformShield']['forms'][$build['#id']] = [
      'id' => $form_id,
      'token' => $build['#webform_shield_token'],
    ];

    // Store the action placeholder as an attribute so that it converts
    // during the building of the form.
    $build['#attributes']['data-action'] = $build['#action'];

    // Change the action so the submission does not go through.
    $build['#action'] = base_path() . 'webform-shield';

    // Add a class to the form.
    $build['#attributes']['class'][] = 'webform-shield';

    return $build;
  }

}