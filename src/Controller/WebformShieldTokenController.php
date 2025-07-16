<?php

namespace Drupal\webform_shield\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Path\PathMatcherInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller for generating Webform Shield tokens via AJAX with enhanced security.
 */
class WebformShieldTokenController extends ControllerBase {

  /**
   * The flood service.
   *
   * @var \Drupal\Core\Flood\FloodInterface
   */
  protected $flood;

  /**
   * The path matcher service.
   *
   * @var \Drupal\Core\Path\PathMatcherInterface
   */
  protected $pathMatcher;

  /**
   * Constructs a WebformShieldTokenController object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Session\AccountInterface $current_user
   *   The current user.
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service.
   * @param \Drupal\Core\Path\PathMatcherInterface $path_matcher
   *   The path matcher service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, AccountInterface $current_user, FloodInterface $flood, PathMatcherInterface $path_matcher) {
    $this->configFactory = $config_factory;
    $this->currentUser = $current_user;
    $this->flood = $flood;
    $this->pathMatcher = $path_matcher;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('current_user'),
      $container->get('flood'),
      $container->get('path.matcher')
    );
  }

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
      $client_ip = $request->getClientIp();
      $user_agent = $request->headers->get('User-Agent', '');
      
      // Enhanced security logging
      $this->getLogger('webform_shield')->info('Token request: IP=@ip, User-Agent=@ua, Form=@form, User=@user', [
        '@ip' => $client_ip,
        '@ua' => substr($user_agent, 0, 255),
        '@form' => $form_id,
        '@user' => $this->currentUser()->id(),
      ]);

      // Validate request method
      if (!$request->isMethod('POST')) {
        $this->logSecurityEvent('Invalid request method: ' . $request->getMethod(), $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid request method',
        ], 405);
      }

      // Validate AJAX request headers
      if (!$request->headers->has('X-Requested-With') || 
          $request->headers->get('X-Requested-With') !== 'XMLHttpRequest') {
        $this->logSecurityEvent('Non-AJAX request detected', $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid request headers',
        ], 400);
      }

      // Validate CSRF token in header
      if (!$request->headers->has('X-CSRF-Token')) {
        $this->logSecurityEvent('Missing CSRF token in header', $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Missing security token',
        ], 400);
      }

      // Additional origin validation
      $origin = $request->headers->get('Origin');
      $referer = $request->headers->get('Referer');
      $currentDomain = $request->getSchemeAndHttpHost();
      
      if ($origin && !str_starts_with($origin, $currentDomain)) {
        $this->logSecurityEvent('Cross-origin request detected: ' . $origin, $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid origin',
        ], 403);
      }

      if ($referer && !str_starts_with($referer, $currentDomain)) {
        $this->logSecurityEvent('Invalid referer detected: ' . $referer, $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid referer',
        ], 403);
      }

      // Rate limiting check
      $flood_identifier = 'webform_shield.token_request';
      $flood_window = 3600; // 1 hour
      $flood_threshold = 100; // 100 requests per hour per IP

      if ($this->flood->isAllowed($flood_identifier, $flood_threshold, $flood_window, $client_ip)) {
        $this->flood->register($flood_identifier, $flood_window, $client_ip);
      } else {
        $this->logSecurityEvent('Rate limit exceeded', $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Too many requests',
        ], 429);
      }

      // Validate form ID with stricter regex
      if (empty($form_id) || !preg_match('/^[a-zA-Z0-9_-]+(\*)?$/', $form_id)) {
        $this->logSecurityEvent('Invalid form ID format: ' . $form_id, $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid form identifier',
        ], 400);
      }

      // Check if this form should be protected.
      $config = $this->config('webform_shield.settings');
      $form_ids = $config->get('form_ids') ?? [];
      $excluded_form_ids = $config->get('excluded_form_ids') ?? [];

      if (empty($form_ids)) {
        $this->logSecurityEvent('No forms configured for protection', $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Service not configured',
        ], 400);
      }

      // Check if this form/pattern is a match.
      $included = FALSE;
      $excluded = FALSE;
      
      // Check if the incoming form_id matches any of our configured patterns
      foreach ($form_ids as $pattern) {
        if ($form_id === $pattern || $this->pathMatcher->matchPath($form_id, $pattern)) {
          $included = TRUE;
          break;
        }
      }
      
      // Check exclusions
      foreach ($excluded_form_ids as $pattern) {
        if ($form_id === $pattern || $this->pathMatcher->matchPath($form_id, $pattern)) {
          $excluded = TRUE;
          break;
        }
      }

      if (!$included || $excluded) {
        $this->logSecurityEvent('Form not protected by configuration: ' . $form_id, $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Form not protected',
        ], 400);
      }

      // Check if user has skip permission.
      if ($this->currentUser()->hasPermission('skip webform shield')) {
        $this->getLogger('webform_shield')->notice('User has skip permission: User=@user, Form=@form', [
          '@user' => $this->currentUser()->id(),
          '@form' => $form_id,
        ]);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'User has skip permission',
        ], 403);
      }

      // Additional security: Check session exists for anonymous users
      if ($this->currentUser()->isAnonymous()) {
        $session = $request->getSession();
        if (!$session->isStarted()) {
          $session->start();
        }
      }

      // Generate the token using the form_id (pattern or literal)
      $token = _webform_shield_generate_token($form_id);
      
      // Log successful token generation
      $this->getLogger('webform_shield')->info('Token generated successfully: Form=@form, User=@user, IP=@ip', [
        '@form' => $form_id,
        '@user' => $this->currentUser()->id(),
        '@ip' => $client_ip,
      ]);

      // Set security headers
      $response = new JsonResponse([
        'success' => TRUE,
        'token' => $token,
      ]);

      // Add security headers to response
      $response->headers->set('X-Content-Type-Options', 'nosniff');
      $response->headers->set('X-Frame-Options', 'DENY');
      $response->headers->set('X-XSS-Protection', '1; mode=block');
      $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

      return $response;

    }
    catch (\Exception $e) {
      $this->logSecurityEvent('Token generation error: ' . $e->getMessage(), $request, $form_id);
      
      // Log the full exception for debugging (but don't expose to client)
      $this->getLogger('webform_shield')->error('Token generation exception: @message | @trace', [
        '@message' => $e->getMessage(),
        '@trace' => $e->getTraceAsString(),
      ]);

      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Internal server error',
      ], 500);
    }
  }

  /**
   * Log security events for monitoring.
   *
   * @param string $message
   *   The security event message.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   * @param string $form_id
   *   The form ID.
   */
  private function logSecurityEvent($message, Request $request, $form_id) {
    $this->getLogger('webform_shield')->warning('Security event: @message | IP=@ip, UA=@ua, Form=@form, User=@user, Referer=@referer', [
      '@message' => $message,
      '@ip' => $request->getClientIp(),
      '@ua' => substr($request->headers->get('User-Agent', ''), 0, 255),
      '@form' => $form_id,
      '@user' => $this->currentUser()->id(),
      '@referer' => substr($request->headers->get('Referer', ''), 0, 255),
    ]);
  }

}