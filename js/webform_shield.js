/**
 * @file
 * Unlock protected forms with enhanced security.
 *
 * This works by resetting the form action to the path that it should be as well
 * as injecting the secret form token via AJAX with CSRF protection, only if the 
 * current user is verified to be human which is done by waiting for a mousemove, 
 * swipe, or tab/enter key to be pressed.
 */

((Drupal, drupalSettings) => {
  drupalSettings.webformShield = drupalSettings.webformShield || {};
  Drupal.webformShield = {};

  // Cache for CSRF token to avoid multiple requests
  let csrfTokenCache = null;
  let csrfTokenPromise = null;

  /**
   * Debug logging function that respects the debug mode setting.
   */
  function debugLog(message, ...args) {
    if (drupalSettings.webformShield && drupalSettings.webformShield.debugMode) {
      console.log('Webform Shield Debug:', message, ...args);
    }
  }

  /**
   * Info logging function for important events.
   */
  function infoLog(message, ...args) {
    console.log('Webform Shield:', message, ...args);
  }

  /**
   * Error logging function.
   */
  function errorLog(message, ...args) {
    console.error('Webform Shield Error:', message, ...args);
  }

  /**
   * Warning logging function.
   */
  function warnLog(message, ...args) {
    console.warn('Webform Shield Warning:', message, ...args);
  }

  Drupal.behaviors.webformShield = {
    attach(context, settings) {
      drupalSettings = settings;
      // Assume the user is not human, despite JS being enabled.
      drupalSettings.webformShield.human = false;

      if (drupalSettings.webformShield.debugMode) {
        infoLog('Behavior attached, waiting for human interaction...');
      }
      
      // Debug information
      if (drupalSettings.webformShield.debugMode) {
        debugLog('Debug mode enabled');
        debugLog('Configuration:', drupalSettings.webformShield.debugInfo);
        debugLog('Current user permissions and settings loaded');
      }

      // Wait for a mouse to move, indicating they are human.
      document.body.addEventListener('mousemove', () => {
        if (drupalSettings.webformShield.debugMode) {
          debugLog('Mouse movement detected');
        }
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // Wait for a touch move event, indicating that they are human.
      document.body.addEventListener('touchmove', () => {
        if (drupalSettings.webformShield.debugMode) {
          debugLog('Touch movement detected');
        }
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // A tab or enter key pressed can also indicate they are human.
      document.body.addEventListener('keydown', (e) => {
        if (e.code === 'Tab' || e.code === 'Enter') {
          if (drupalSettings.webformShield.debugMode) {
            debugLog('Key interaction detected:', e.code);
          }
          // Unlock the forms.
          Drupal.webformShield.unlockForms();
        }
      });

      // Mouse click also indicates human behavior.
      document.body.addEventListener('click', () => {
        if (drupalSettings.webformShield.debugMode) {
          debugLog('Click detected');
        }
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // Scroll event can also indicate human behavior.
      document.addEventListener('scroll', () => {
        if (drupalSettings.webformShield.debugMode) {
          debugLog('Scroll detected');
        }
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });
    },
  };

  /**
   * Get CSRF token with caching to avoid multiple requests.
   */
  Drupal.webformShield.getCsrfToken = () => {
    // Return cached token if available
    if (csrfTokenCache) {
      if (drupalSettings.webformShield.debugMode) {
        debugLog('Using cached CSRF token');
      }
      return Promise.resolve(csrfTokenCache);
    }

    // Return existing promise if request is in progress
    if (csrfTokenPromise) {
      if (drupalSettings.webformShield.debugMode) {
        debugLog('CSRF token request already in progress');
      }
      return csrfTokenPromise;
    }

    if (drupalSettings.webformShield.debugMode) {
      debugLog('Fetching new CSRF token from:', `${drupalSettings.path.baseUrl}session/token`);
    }

    // Create new request for CSRF token
    csrfTokenPromise = fetch(`${drupalSettings.path.baseUrl}session/token`, {
      method: 'GET',
      credentials: 'same-origin',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
      },
    })
    .then(response => {
      if (drupalSettings.webformShield.debugMode) {
        debugLog('CSRF token response status:', response.status);
      }
      if (!response.ok) {
        throw new Error(`Failed to get CSRF token: ${response.status}`);
      }
      return response.text();
    })
    .then(token => {
      if (drupalSettings.webformShield.debugMode) {
        debugLog('CSRF token received successfully');
      }
      csrfTokenCache = token;
      csrfTokenPromise = null; // Clear the promise after success
      return token;
    })
    .catch(error => {
      if (drupalSettings.webformShield.debugMode) {
        errorLog('Error getting CSRF token:', error);
      }
      csrfTokenPromise = null; // Clear the promise after error
      throw error;
    });

    return csrfTokenPromise;
  };

  /**
   * Unlock all locked forms by fetching tokens via AJAX with CSRF protection.
   */
  Drupal.webformShield.unlockForms = () => {
    // Act only if we haven't yet verified this user as being human.
    if (!drupalSettings.webformShield.human) {
      if (drupalSettings.webformShield.debugMode) {
        infoLog('Human interaction detected, attempting to unlock forms...');
      }
      
      // Find all webform shield protected forms.
      const forms = document.querySelectorAll('form.webform-shield');
      if (drupalSettings.webformShield.debugMode) {
        infoLog('Found', forms.length, 'protected forms');
      }
      
      if (forms.length === 0) {
        if (drupalSettings.webformShield.debugMode) {
          debugLog('No protected forms found, marking user as human');
        }
        drupalSettings.webformShield.human = true;
        return;
      }

      // Debug: Log form details
      if (drupalSettings.webformShield.debugMode) {
        forms.forEach((form, index) => {
          const formId = form.getAttribute('data-form-id');
          const originalAction = form.getAttribute('data-action');
          const currentAction = form.getAttribute('action');
          if (drupalSettings.webformShield.debugMode) {
            debugLog(`Form ${index + 1}:`, {
              formId,
              originalAction,
              currentAction,
              hasTokenInput: !!form.querySelector('input[name="webform_shield_token"]'),
              classes: form.className
            });
          }
        });
      }

      // Get CSRF token first
      Drupal.webformShield.getCsrfToken()
        .then(csrfToken => {
          if (drupalSettings.webformShield.debugMode) {
            debugLog('CSRF token obtained, processing forms...');
          }
          
          // Process each form with the CSRF token
          forms.forEach((form, index) => {
            const formId = form.getAttribute('data-form-id');
            const originalAction = form.getAttribute('data-action');
            const tokenInput = form.querySelector('input[name="webform_shield_token"]');
            
            if (formId && originalAction && tokenInput) {
              // Build the token URL (no query parameter needed for header token)
              const tokenUrl = `${drupalSettings.path.baseUrl}webform-shield/token/${formId}`;
              
              if (drupalSettings.webformShield.debugMode) {
                debugLog(`Processing form ${index + 1}/${forms.length}:`, {
                  formId,
                  tokenUrl,
                  originalAction
                });
              }
              
              // Fetch token via AJAX with enhanced security.
              fetch(tokenUrl, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/x-www-form-urlencoded',
                  'X-Requested-With': 'XMLHttpRequest',
                  'X-CSRF-Token': csrfToken,
                },
                credentials: 'same-origin',
                referrerPolicy: 'strict-origin-when-cross-origin',
              })
              .then(response => {
                if (drupalSettings.webformShield.debugMode) {
                  debugLog(`Form ${index + 1} token response status:`, response.status);
                }
                
                if (!response.ok) {
                  // Get the error response text for debugging
                  return response.text().then(text => {
                    errorLog(`Form ${index + 1} token error response:`, text);
                    throw new Error(`HTTP error! status: ${response.status}, body: ${text}`);
                  });
                }
                return response.json();
              })
              .then(data => {
                if (drupalSettings.webformShield.debugMode) {
                  debugLog(`Form ${index + 1} token response data:`, data);
                }
                
                if (data.success && data.token) {
                  // Restore original form action.
                  form.setAttribute('action', originalAction);
                  
                  // Set the token.
                  tokenInput.value = data.token;
                  
                  // Mark form as unlocked.
                  form.classList.add('webform-shield-unlocked');

                  if (drupalSettings.webformShield.debugMode) {
                    infoLog(`Form unlocked successfully for: ${formId}`);
                    debugLog(`Form ${index + 1} unlocked:`, {
                      formId,
                      tokenSet: !!tokenInput.value,
                      actionRestored: form.getAttribute('action') === originalAction,
                      unlocked: form.classList.contains('webform-shield-unlocked')
                    });
                  }
                } else {
                  if (drupalSettings.webformShield.debugMode) {
                    warnLog(`Failed to get token for form ${formId}:`, data.error || 'Unknown error');
                  }
                }
              })
              .catch(error => {
                errorLog(`Error fetching token for form ${formId}:`, error);
                // Form remains locked if token fetch fails.
              });
            } else {
              if (drupalSettings.webformShield.debugMode) {
                warnLog(`Form ${index + 1} missing required attributes:`, {
                  formId: formId ? 'present' : 'missing',
                  originalAction: originalAction ? 'present' : 'missing',
                  tokenInput: tokenInput ? 'present' : 'missing'
                });
              }
            }
          });
          
          // Mark this user as being human.
          drupalSettings.webformShield.human = true;
          if (drupalSettings.webformShield.debugMode) {
            infoLog('User marked as human');
            debugLog('Form unlocking process completed');
          }
        })
        .catch(error => {
          errorLog('Error getting CSRF token:', error);
          // Don't mark as human if CSRF token fetch fails
        });
    } else {
      if (drupalSettings.webformShield.debugMode) {
        debugLog('User already verified as human, skipping unlock');
      }
    }
  };
})(Drupal, drupalSettings);