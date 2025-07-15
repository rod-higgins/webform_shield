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

    // Store the form ID for AJAX token generation.
    $form_id = $build['#id'];
    if (isset($build['#attributes']['id'])) {
      $form_id = $build['#attributes']['id'];
    }

    // Store original action and form ID as data attributes for JavaScript.
    $build['#attributes']['data-action'] = $build['#action'];
    $build['#attributes']['data-form-id'] = $build['#form_id'];
    
    // Change the action so the submission does not go through.
    $build['#action'] = base_path() . 'webform-shield';

    // Add a class to the form.
    $build['#attributes']['class'][] = 'webform-shield';

    return $build;
  }

}