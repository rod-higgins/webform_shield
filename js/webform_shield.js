/**
 * @file
 * Unlock protected forms.
 *
 * This works by resetting the form action to the path that it should be as well
 * as injecting the secret form token via AJAX, only if the current user is 
 * verified to be human which is done by waiting for a mousemove, swipe, or 
 * tab/enter key to be pressed.
 */

((Drupal, drupalSettings) => {
  drupalSettings.webformShield = drupalSettings.webformShield || {};
  Drupal.webformShield = {};

  Drupal.behaviors.webformShield = {
    attach(context, settings) {
      drupalSettings = settings;
      // Assume the user is not human, despite JS being enabled.
      drupalSettings.webformShield.human = false;

      console.log('Webform Shield: Behavior attached, waiting for human interaction...');

      // Wait for a mouse to move, indicating they are human.
      document.body.addEventListener('mousemove', () => {
        console.log('Webform Shield: Mouse movement detected');
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // Wait for a touch move event, indicating that they are human.
      document.body.addEventListener('touchmove', () => {
        console.log('Webform Shield: Touch movement detected');
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // A tab or enter key pressed can also indicate they are human.
      document.body.addEventListener('keydown', (e) => {
        if (e.code === 'Tab' || e.code === 'Enter') {
          console.log('Webform Shield: Key interaction detected:', e.code);
          // Unlock the forms.
          Drupal.webformShield.unlockForms();
        }
      });

      // Mouse click also indicates human behavior.
      document.body.addEventListener('click', () => {
        console.log('Webform Shield: Click detected');
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });

      // Scroll event can also indicate human behavior.
      document.addEventListener('scroll', () => {
        console.log('Webform Shield: Scroll detected');
        // Unlock the forms.
        Drupal.webformShield.unlockForms();
      });
    },
  };

  /**
   * Unlock all locked forms by fetching tokens via AJAX.
   */
  Drupal.webformShield.unlockForms = () => {
    // Act only if we haven't yet verified this user as being human.
    if (!drupalSettings.webformShield.human) {
      console.log('Webform Shield: Attempting to unlock forms...');
      
      // Find all webform shield protected forms.
      const forms = document.querySelectorAll('form.webform-shield');
      console.log('Webform Shield: Found', forms.length, 'protected forms');
      
      forms.forEach((form, index) => {
        const formId = form.getAttribute('data-form-id');
        const originalAction = form.getAttribute('data-action');
        const tokenInput = form.querySelector('input[name="webform_shield_token"]');
        
        // Debug: Log what we found
        console.log('Webform Shield: Processing form', index + 1, '/', forms.length, {
          formId: formId,
          originalAction: originalAction,
          tokenInput: tokenInput ? 'found' : 'missing',
          baseUrl: drupalSettings.path.baseUrl
        });
        
        if (formId && originalAction && tokenInput) {
          // Build the token URL
          const tokenUrl = `${drupalSettings.path.baseUrl}webform-shield/token/${formId}`;
          console.log('Webform Shield: Fetching token from:', tokenUrl);
          
          // Fetch token via AJAX.
          fetch(tokenUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'X-Requested-With': 'XMLHttpRequest',
            },
            credentials: 'same-origin',
          })
          .then(response => {
            console.log('Webform Shield: Token response status:', response.status);
            
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
            console.log('Webform Shield: Token response data:', data);
            
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
    } else {
      console.log('Webform Shield: User already verified as human, skipping unlock');
    }
  };
})(Drupal, drupalSettings);