<?php

/**
 * @file
 * Hooks and documentation related to webform_shield.
 */

/**
 * Modify the webform shield protection of the form.
 *
 * @param string $form_id
 *   The form ID of the form.
 * @param bool $protection
 *   The protection of the form passed by parameter.
 */
function hook_webform_shield_form_status_alter(string $form_id, bool &$protection) {
  if ($form_id === 'my_form_id') {
    $protection = TRUE;
  }
}