<?php

namespace Drupal\webform_shield\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller for generating Webform Shield tokens via AJAX.
 */
class WebformShieldTokenController extends ControllerBase {

  /**
   * Generate a token for a specific form.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   * @param string $form_id
   *   The form ID to generate a token for.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response containing the token.
   */
  public function generateToken(Request $request, $form_id) {
    try {
      // Validate that this is a POST request.
      if (!$request->isMethod('POST')) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid request method',
        ], 405);
      }

      // Validate form ID.
      if (empty($form_id) || !preg_match('/^[a-zA-Z0-9_-]+$/', $form_id)) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid form ID',
        ], 400);
      }

      // Check if this form should be protected.
      $config = $this->config('webform_shield.settings');
      $form_ids = $config->get('form_ids') ?? [];
      $excluded_form_ids = $config->get('excluded_form_ids') ?? [];

      if (empty($form_ids)) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'No forms configured for protection',
        ], 400);
      }

      // Check if this form is a match.
      $pathMatcher = \Drupal::service('path.matcher');
      $included = $pathMatcher->matchPath($form_id, implode("\n", $form_ids));
      $excluded = $pathMatcher->matchPath($form_id, implode("\n", $excluded_form_ids));

      if (!$included || $excluded) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Form not protected by Webform Shield',
        ], 400);
      }

      // Check if user has skip permission.
      if ($this->currentUser()->hasPermission('skip webform shield')) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'User has skip permission',
        ], 403);
      }

      // Generate the token.
      $token = _webform_shield_generate_token($form_id);

      return new JsonResponse([
        'success' => TRUE,
        'token' => $token,
      ]);

    }
    catch (\Exception $e) {
      // Log the error.
      $this->getLogger('webform_shield')->error('Token generation error: @message', [
        '@message' => $e->getMessage(),
      ]);

      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Internal server error',
      ], 500);
    }
  }

}