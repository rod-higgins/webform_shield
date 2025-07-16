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

  Drupal.behaviors.webformShield = {
    attach(context, settings) {
      drupalSettings = settings;
      // Assume the user is not human, despite JS being enabled.
      drupalSettings.webformShield.human = false;

      console.log('Webform Shield: Behavior attached, waiting for human interaction...');

      // Wait for a mouse to move, indicating they are human.
      document.body.addEventListener('mousemove', () => {
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // Wait for a touch move event, indicating that they are human.
      document.body.addEventListener('touchmove', () => {
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // A tab or enter key pressed can also indicate they are human.
      document.body.addEventListener('keydown', (e) => {
        if (e.code === 'Tab' || e.code === 'Enter') {
          // Unlock the forms.
          Drupal.webformShield.unlockForms();
        }
      });

      // Mouse click also indicates human behavior.
      document.body.addEventListener('click', () => {
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // Scroll event can also indicate human behavior.
      document.addEventListener('scroll', () => {
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
      return Promise.resolve(csrfTokenCache);
    }

    // Return existing promise if request is in progress
    if (csrfTokenPromise) {
      return csrfTokenPromise;
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
      if (!response.ok) {
        throw new Error(`Failed to get CSRF token: ${response.status}`);
      }
      return response.text();
    })
    .then(token => {
      csrfTokenCache = token;
      csrfTokenPromise = null; // Clear the promise after success
      return token;
    })
    .catch(error => {
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
      console.log('Webform Shield: Human interaction detected, attempting to unlock forms...');
      
      // Find all webform shield protected forms.
      const forms = document.querySelectorAll('form.webform-shield');
      console.log('Webform Shield: Found', forms.length, 'protected forms');
      
      if (forms.length === 0) {
        drupalSettings.webformShield.human = true;
        return;
      }

      // Get CSRF token first
      Drupal.webformShield.getCsrfToken()
        .then(csrfToken => {
          // Process each form with the CSRF token
          forms.forEach((form, index) => {
            const formId = form.getAttribute('data-form-id');
            const originalAction = form.getAttribute('data-action');
            const tokenInput = form.querySelector('input[name="webform_shield_token"]');
            
            if (formId && originalAction && tokenInput) {
              // Build the token URL with CSRF token as query parameter
              const tokenUrl = `${drupalSettings.path.baseUrl}webform-shield/token/${formId}?token=${encodeURIComponent(csrfToken)}`;
              
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
                if (!response.ok) {
                  // Get the error response text for debugging
                  return response.text().then(text => {
                    console.error('Webform Shield: Token error response:', text);
                    throw new Error(`HTTP error! status: ${response.status}, body: ${text}`);
                  });
                }
                return response.json();
              })
              .then(data => {
                if (data.success && data.token) {
                  // Restore original form action.
                  form.setAttribute('action', originalAction);
                  
                  // Set the token.
                  tokenInput.value = data.token;
                  
                  // Mark form as unlocked.
                  form.classList.add('webform-shield-unlocked');
                  
                  console.log('Webform Shield: Form unlocked successfully for:', formId);
                } else {
                  console.warn('Webform Shield: Failed to get token for form', formId, data.error || 'Unknown error');
                }
              })
              .catch(error => {
                console.error('Webform Shield: Error fetching token for form', formId, error);
                // Form remains locked if token fetch fails.
              });
            } else {
              console.warn('Webform Shield: Form missing required attributes:', {
                formId: formId ? 'present' : 'missing',
                originalAction: originalAction ? 'present' : 'missing',
                tokenInput: tokenInput ? 'present' : 'missing'
              });
            }
          });
          
          // Mark this user as being human.
          drupalSettings.webformShield.human = true;
          console.log('Webform Shield: User marked as human');
        })
        .catch(error => {
          console.error('Webform Shield: Error getting CSRF token:', error);
          // Don't mark as human if CSRF token fetch fails
        });
    }
  };
})(Drupal, drupalSettings);