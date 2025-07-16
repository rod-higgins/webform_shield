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
   *   The form ID or pattern to generate a token for.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response containing the token.
   */
  public function generateToken(Request $request, $form_id) {
    try {
      // Log the incoming request for debugging
      \Drupal::logger('webform_shield')->notice('Token request: method=@method, form_id=@form_id', [
        '@method' => $request->getMethod(),
        '@form_id' => $form_id,
      ]);

      // Validate that this is a POST request.
      if (!$request->isMethod('POST')) {
        \Drupal::logger('webform_shield')->error('Token request not POST method: @method', ['@method' => $request->getMethod()]);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid request method',
        ], 405);
      }

      // Validate form ID.
      if (empty($form_id) || !preg_match('/^[a-zA-Z0-9_*-]+$/', $form_id)) {
        \Drupal::logger('webform_shield')->error('Invalid form ID: @form_id', ['@form_id' => $form_id]);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid form ID',
        ], 400);
      }

      // Check if this form should be protected.
      $config = $this->config('webform_shield.settings');
      $form_ids = $config->get('form_ids') ?? [];
      $excluded_form_ids = $config->get('excluded_form_ids') ?? [];

      \Drupal::logger('webform_shield')->notice('Config patterns: @patterns', [
        '@patterns' => implode(', ', $form_ids)
      ]);

      if (empty($form_ids)) {
        \Drupal::logger('webform_shield')->error('No forms configured for protection');
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'No forms configured for protection',
        ], 400);
      }

      // Check if this form/pattern is a match.
      $pathMatcher = \Drupal::service('path.matcher');
      
      // The form_id might be a pattern (like "webform_submission_*") or a literal form ID
      // We need to check if it matches any of our configured patterns
      $included = FALSE;
      $excluded = FALSE;
      
      // Check if the incoming form_id matches any of our configured patterns
      foreach ($form_ids as $pattern) {
        if ($form_id === $pattern || $pathMatcher->matchPath($form_id, $pattern)) {
          $included = TRUE;
          break;
        }
      }
      
      // Check exclusions
      foreach ($excluded_form_ids as $pattern) {
        if ($form_id === $pattern || $pathMatcher->matchPath($form_id, $pattern)) {
          $excluded = TRUE;
          break;
        }
      }

      \Drupal::logger('webform_shield')->notice('Form matching - form_id: @form_id, included: @inc, excluded: @exc', [
        '@form_id' => $form_id,
        '@inc' => $included ? 'YES' : 'NO',
        '@exc' => $excluded ? 'YES' : 'NO'
      ]);

      if (!$included || $excluded) {
        \Drupal::logger('webform_shield')->error('Form not protected: @form_id', ['@form_id' => $form_id]);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Form not protected by Webform Shield',
        ], 400);
      }

      // Check if user has skip permission.
      if ($this->currentUser()->hasPermission('skip webform shield')) {
        \Drupal::logger('webform_shield')->notice('User has skip permission');
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'User has skip permission',
        ], 403);
      }

      // Generate the token using the form_id (pattern or literal)
      $token = _webform_shield_generate_token($form_id);
      
      \Drupal::logger('webform_shield')->notice('Token generated successfully for: @form_id', ['@form_id' => $form_id]);

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