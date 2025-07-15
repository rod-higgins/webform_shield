/**
 * @file
 * Unlock protected forms.
 *
 * This works by resetting the form action to the path that it should be as well
 * as injecting the secret form token, only if the current user is verified to be
 * human which is done by waiting for a mousemove, swipe, or tab/enter key to be
 * pressed.
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
   * Unlock all locked forms.
   */
  Drupal.webformShield.unlockForms = () => {
    // Act only if we haven't yet verified this user as being human.
    if (!drupalSettings.webformShield.human) {
      // Check if there are forms to unlock.
      if (drupalSettings.webformShield.forms !== undefined) {
        // Iterate all webform shield forms that we need to unlock.
        Object.values(drupalSettings.webformShield.forms).forEach((config) => {
          // Switch the action.
          const form = document.getElementById(config.id);
          if (form) {
            form.setAttribute('action', form.getAttribute('data-action'));

            // Set the token.
            const input = form.querySelector('input[name="webform_shield_token"]');
            if (input) {
              input.value = config.token;
            }
          }
        });
      }
      // Mark this user as being human.
      drupalSettings.webformShield.human = true;
    }
  };
})(Drupal, drupalSettings);