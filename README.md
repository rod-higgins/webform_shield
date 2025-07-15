# Webform Shield

Webform Shield is an advanced spam protection module for Drupal that prevents robotic form submissions using encrypted dynamic keys with configurable timeouts. The module works completely behind the scenes and requires human-like interaction from end-users.

## Features

- **Encrypted Dynamic Keys**: Server-side generated tokens with built-in expiration
- **Configurable Timeouts**: Set token expiration times from 1-60 minutes
- **Human Behavior Detection**: Detects mouse movement, touch, keyboard, clicks, and scrolling
- **Automatic Cleanup**: Expired tokens are automatically removed via cron
- **Session Validation**: Additional security layer using session IDs
- **One-time Use Tokens**: Tokens are consumed upon successful validation
- **Cache Integration**: Uses Drupal's cache system for token storage

## Requirements

This module requires no modules outside of Drupal core.

## Installation

Install as you would normally install a contributed Drupal module:

1. Extract the module to your `modules/custom` directory
2. Enable the module via the admin interface or drush: `drush en webform_shield`

## Configuration

1. Navigate to Administration » Configuration » User Interface » Webform Shield
2. Configure the following settings:

### Form IDs
Specify the form IDs that should be protected by Webform Shield. Each form ID should be on a separate line. Wildcard (*) characters can be used.

Default protected forms:
- `comment_*` - All comment forms
- `user_login_form` - User login form  
- `user_pass` - Password reset form
- `user_register_form` - User registration form
- `contact_message_*` - All contact forms
- `webform_*` - All webforms

### Excluded Form IDs
Specify form IDs that should never be protected, even if they match the inclusion patterns.

### Token Timeout
Configure how long tokens remain valid before expiring (60-3600 seconds). Default is 900 seconds (15 minutes).

### Display Form IDs
Temporarily enable this to see all form IDs on pages for easier configuration.

## Permissions

Configure these permissions under Administration » People » Permissions:

- **Administer Webform Shield configuration**: Allows access to module settings
- **Skip Webform Shield**: Bypasses protection for users with this permission

## How It Works

1. **Form Protection**: Protected forms have their action changed to `/webform-shield` and receive an empty hidden token field
2. **Human Detection**: JavaScript waits for human behavior (mouse movement, touch, keyboard, clicks, scrolling)
3. **Token Injection**: Upon human interaction, the original form action is restored and the token is populated
4. **Server Validation**: Form submission validates the token exists, hasn't expired, and matches the session
5. **Token Cleanup**: Used tokens are immediately deleted; expired tokens are cleaned up via cron

## Security Features

- **Server-side Generation**: Tokens are generated server-side with cryptographic randomness
- **Expiration Control**: Configurable timeouts prevent token reuse attacks
- **Session Binding**: Tokens are tied to user sessions for additional security
- **One-time Use**: Tokens are consumed upon successful validation
- **Cache Storage**: Uses Drupal's cache system with automatic expiration

## JavaScript Requirements

Users must have JavaScript enabled. Without JavaScript:
- Protected forms are hidden via CSS
- A warning message is displayed
- Form submission will fail

## Troubleshooting

### Forms Not Being Protected
1. Check that the form ID matches your configuration patterns
2. Verify the user doesn't have "Skip Webform Shield" permission
3. Enable "Display form IDs" temporarily to see actual form IDs

### Token Validation Failures
1. Check token timeout settings aren't too short
2. Verify cron is running to clean up expired tokens
3. Check for session-related issues

### JavaScript Not Working
1. Ensure the Webform Shield library is loading
2. Check for JavaScript errors in browser console
3. Verify human interaction events are being detected

## API

### Alter Hook
Other modules can modify form protection using the alter hook:

```php
/**
 * Implements hook_webform_shield_form_status_alter().
 */
function mymodule_webform_shield_form_status_alter(string $form_id, bool &$protection) {
  if ($form_id === 'my_custom_form') {
    $protection = TRUE;
  }
}
```

## Differences from Antibot

While inspired by the Antibot module, Webform Shield provides enhanced security:

- **Server-side Token Management**: Tokens are generated and validated server-side
- **Configurable Expiration**: Flexible timeout settings
- **Enhanced Validation**: Session binding and cryptographic verification
- **Automatic Cleanup**: Built-in token lifecycle management
- **Multiple Human Triggers**: More interaction types detected

## Maintenance

- Expired tokens are automatically cleaned up via cron
- Monitor token timeout settings based on your user behavior patterns
- Regularly review protected form patterns as your site evolves

## Support

For issues and feature requests, please use the module's issue queue or contact the maintainers.