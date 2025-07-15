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
   * Unlock all locked forms by fetching tokens via AJAX.
   */
  Drupal.webformShield.unlockForms = () => {
    // Act only if we haven't yet verified this user as being human.
    if (!drupalSettings.webformShield.human) {
      // Find all webform shield protected forms.
      const forms = document.querySelectorAll('form.webform-shield');
      
      forms.forEach((form) => {
        const formId = form.getAttribute('data-form-id');
        const originalAction = form.getAttribute('data-action');
        const tokenInput = form.querySelector('input[name="webform_shield_token"]');
        
        if (formId && originalAction && tokenInput) {
          // Fetch token via AJAX.
          fetch(`${drupalSettings.path.baseUrl}webform-shield/token/${formId}`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest',
            },
            credentials: 'same-origin',
          })
          .then(response => {
            if (!response.ok) {
              throw new Error(`HTTP error! status: ${response.status}`);
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
            } else {
              console.warn('Webform Shield: Failed to get token for form', formId, data.error || 'Unknown error');
            }
          })
          .catch(error => {
            console.error('Webform Shield: Error fetching token for form', formId, error);
            // Form remains locked if token fetch fails.
          });
        }
      });
      
      // Mark this user as being human.
      drupalSettings.webformShield.human = true;
    }
  };
})(Drupal, drupalSettings);