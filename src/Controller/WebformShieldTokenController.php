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
   *   The form pattern or ID to generate a token for.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response containing the token.
   */
  public function generateToken(Request $request, $form_id) {
    $config = $this->config('webform_shield.settings');
    $debug_mode = $config->get('debug_mode') ?: FALSE;
    
    try {
      $client_ip = $request->getClientIp();
      $user_agent = $request->headers->get('User-Agent', '');
      
      // Log token requests (only in debug mode)
      if ($debug_mode) {
        $this->getLogger('webform_shield')->info('Token request: IP=@ip, User-Agent=@ua, Pattern=@pattern, User=@user', [
          '@ip' => $client_ip,
          '@ua' => substr($user_agent, 0, 255),
          '@pattern' => $form_id,
          '@user' => $this->currentUser()->id(),
        ]);
      }

      // Debug logging for request details (only in debug mode)
      if ($debug_mode) {
        $this->getLogger('webform_shield')->debug('Token request debug: Method=@method, Headers=@headers, Origin=@origin', [
          '@method' => $request->getMethod(),
          '@headers' => json_encode($request->headers->all()),
          '@origin' => $request->headers->get('Origin', 'none'),
        ]);
      }

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

      // Note: CSRF validation is handled automatically by _csrf_request_header_token in routing

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

      // Rate limiting check with IP exclusions
      $flood_identifier = 'webform_shield.token_request';
      $flood_window = 3600; // 1 hour
      $flood_threshold = $config->get('rate_limit_threshold') ?: 100;

      if ($config->get('rate_limit_enabled') !== FALSE) {
        // Check if this IP is excluded from rate limiting
        $is_excluded = $this->isIpExcludedFromRateLimit($client_ip, $config);
        
        if ($debug_mode) {
          $this->getLogger('webform_shield')->debug('Rate limit check: IP=@ip, Excluded=@excluded', [
            '@ip' => $client_ip,
            '@excluded' => $is_excluded ? 'yes' : 'no',
          ]);
        }
        
        if (!$is_excluded) {
          if ($this->flood->isAllowed($flood_identifier, $flood_threshold, $flood_window, $client_ip)) {
            $this->flood->register($flood_identifier, $flood_window, $client_ip);
            
            if ($debug_mode) {
              $this->getLogger('webform_shield')->debug('Rate limit check passed for IP: @ip', ['@ip' => $client_ip]);
            }
          } else {
            $this->logSecurityEvent('Rate limit exceeded', $request, $form_id);
            return new JsonResponse([
              'success' => FALSE,
              'error' => 'Too many requests',
            ], 429);
          }
        } else {
          if ($debug_mode) {
            $this->getLogger('webform_shield')->debug('Rate limiting bypassed for excluded IP: @ip', ['@ip' => $client_ip]);
          }
        }
      } else {
        if ($debug_mode) {
          $this->getLogger('webform_shield')->debug('Rate limiting disabled');
        }
      }

      // Validate form pattern with stricter regex
      if (empty($form_id) || !preg_match('/^[a-zA-Z0-9_-]+(\*)?$/', $form_id)) {
        $this->logSecurityEvent('Invalid form pattern format: ' . $form_id, $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid form identifier',
        ], 400);
      }

      // Check if this form should be protected.
      $form_ids = $config->get('form_ids') ?? [];
      $excluded_form_ids = $config->get('excluded_form_ids') ?? [];

      if ($debug_mode) {
        $this->getLogger('webform_shield')->debug('Form protection check: Pattern=@pattern, Patterns=@patterns, Exclusions=@exclusions', [
          '@pattern' => $form_id,
          '@patterns' => implode(', ', $form_ids),
          '@exclusions' => implode(', ', $excluded_form_ids),
        ]);
      }

      if (empty($form_ids)) {
        $this->logSecurityEvent('No forms configured for protection', $request, $form_id);
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Service not configured',
        ], 400);
      }

      // Check if the incoming form_pattern matches any of our configured patterns
      $included = FALSE;
      $excluded = FALSE;
      
      // Check if the incoming form_pattern matches any of our configured patterns
      foreach ($form_ids as $pattern) {
        if ($form_id === $pattern || $this->pathMatcher->matchPath($form_id, $pattern)) {
          $included = TRUE;
          if ($debug_mode) {
            $this->getLogger('webform_shield')->debug('Form matched inclusion pattern: @pattern', ['@pattern' => $pattern]);
          }
          break;
        }
      }
      
      // Check exclusions
      foreach ($excluded_form_ids as $pattern) {
        if ($form_id === $pattern || $this->pathMatcher->matchPath($form_id, $pattern)) {
          $excluded = TRUE;
          if ($debug_mode) {
            $this->getLogger('webform_shield')->debug('Form matched exclusion pattern: @pattern', ['@pattern' => $pattern]);
          }
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
        if ($debug_mode) {
          $this->getLogger('webform_shield')->notice('User has skip permission: User=@user, Pattern=@pattern', [
            '@user' => $this->currentUser()->id(),
            '@pattern' => $form_id,
          ]);
        }
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
          if ($debug_mode) {
            $this->getLogger('webform_shield')->debug('Started session for anonymous user');
          }
        }
      }

      // Generate the token using the form_pattern (this is the key fix!)
      $token = _webform_shield_generate_token($form_id);
      
      // Log successful token generation (only in debug mode)
      if ($debug_mode) {
        $this->getLogger('webform_shield')->info('Token generated successfully: Pattern=@pattern, User=@user, IP=@ip', [
          '@pattern' => $form_id,
          '@user' => $this->currentUser()->id(),
          '@ip' => $client_ip,
        ]);
      }

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
      
      // Always log the exception for debugging (but only details in debug mode)
      if ($debug_mode) {
        $this->getLogger('webform_shield')->error('Token generation exception: @message | @trace', [
          '@message' => $e->getMessage(),
          '@trace' => $e->getTraceAsString(),
        ]);
        
        $this->getLogger('webform_shield')->debug('Token generation debug: Exception details - @message | @file:@line', [
          '@message' => $e->getMessage(),
          '@file' => $e->getFile(),
          '@line' => $e->getLine(),
        ]);
      } else {
        // Just log the basic error without stack trace
        $this->getLogger('webform_shield')->error('Token generation exception: @message', [
          '@message' => $e->getMessage(),
        ]);
      }

      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Internal server error',
      ], 500);
    }
  }

  /**
   * Check if an IP address is excluded from rate limiting.
   *
   * @param string $client_ip
   *   The client IP address to check.
   * @param \Drupal\Core\Config\Config $config
   *   The configuration object.
   *
   * @return bool
   *   TRUE if the IP is excluded, FALSE otherwise.
   */
  private function isIpExcludedFromRateLimit($client_ip, $config) {
    $excluded_ips = $config->get('rate_limit_excluded_ips') ?? [];
    
    if (empty($excluded_ips)) {
      return FALSE;
    }
    
    $debug_mode = $config->get('debug_mode') ?: FALSE;
    
    foreach ($excluded_ips as $excluded_entry) {
      $excluded_entry = trim($excluded_entry);
      
      if (empty($excluded_entry)) {
        continue;
      }
      
      // Check if it's a CIDR subnet
      if (strpos($excluded_entry, '/') !== FALSE) {
        if ($this->ipInSubnet($client_ip, $excluded_entry)) {
          if ($debug_mode) {
            $this->getLogger('webform_shield')->debug('IP @ip matches excluded subnet @subnet', [
              '@ip' => $client_ip,
              '@subnet' => $excluded_entry,
            ]);
          }
          return TRUE;
        }
      } else {
        // Direct IP comparison
        if ($client_ip === $excluded_entry) {
          if ($debug_mode) {
            $this->getLogger('webform_shield')->debug('IP @ip matches excluded IP @excluded', [
              '@ip' => $client_ip,
              '@excluded' => $excluded_entry,
            ]);
          }
          return TRUE;
        }
      }
    }
    
    return FALSE;
  }

  /**
   * Check if an IP address is within a given subnet (CIDR notation).
   *
   * @param string $ip
   *   The IP address to check.
   * @param string $subnet
   *   The subnet in CIDR notation (e.g., 192.168.1.0/24).
   *
   * @return bool
   *   TRUE if the IP is in the subnet, FALSE otherwise.
   */
  private function ipInSubnet($ip, $subnet) {
    $parts = explode('/', $subnet);
    if (count($parts) !== 2) {
      return FALSE;
    }
    
    $subnet_ip = $parts[0];
    $prefix_length = (int) $parts[1];
    
    // Validate both IPs
    if (!filter_var($ip, FILTER_VALIDATE_IP) || !filter_var($subnet_ip, FILTER_VALIDATE_IP)) {
      return FALSE;
    }
    
    // Handle IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
        filter_var($subnet_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
      
      if ($prefix_length < 0 || $prefix_length > 32) {
        return FALSE;
      }
      
      $ip_long = ip2long($ip);
      $subnet_long = ip2long($subnet_ip);
      
      if ($ip_long === FALSE || $subnet_long === FALSE) {
        return FALSE;
      }
      
      $mask = -1 << (32 - $prefix_length);
      return ($ip_long & $mask) === ($subnet_long & $mask);
    }
    
    // Handle IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && 
        filter_var($subnet_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
      
      if ($prefix_length < 0 || $prefix_length > 128) {
        return FALSE;
      }
      
      $ip_bin = inet_pton($ip);
      $subnet_bin = inet_pton($subnet_ip);
      
      if ($ip_bin === FALSE || $subnet_bin === FALSE) {
        return FALSE;
      }
      
      $bytes_to_check = floor($prefix_length / 8);
      $bits_remainder = $prefix_length % 8;
      
      // Check full bytes
      if ($bytes_to_check > 0) {
        if (substr($ip_bin, 0, $bytes_to_check) !== substr($subnet_bin, 0, $bytes_to_check)) {
          return FALSE;
        }
      }
      
      // Check remaining bits
      if ($bits_remainder > 0 && $bytes_to_check < 16) {
        $mask = 0xFF << (8 - $bits_remainder);
        $ip_byte = ord($ip_bin[$bytes_to_check]);
        $subnet_byte = ord($subnet_bin[$bytes_to_check]);
        
        return ($ip_byte & $mask) === ($subnet_byte & $mask);
      }
      
      return TRUE;
    }
    
    return FALSE;
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
    $this->getLogger('webform_shield')->warning('Security event: @message | IP=@ip, UA=@ua, Pattern=@pattern, User=@user, Referer=@referer', [
      '@message' => $message,
      '@ip' => $request->getClientIp(),
      '@ua' => substr($request->headers->get('User-Agent', ''), 0, 255),
      '@pattern' => $form_id,
      '@user' => $this->currentUser()->id(),
      '@referer' => substr($request->headers->get('Referer', ''), 0, 255),
    ]);
  }

}