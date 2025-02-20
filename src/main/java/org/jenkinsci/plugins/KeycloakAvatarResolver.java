
package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.model.User;
import hudson.tasks.UserAvatarResolver;

@Extension
public class KeycloakAvatarResolver extends UserAvatarResolver {
    @Override
    public String findAvatarFor(User user, int width, int height) {
        if (user != null) {
            KeycloakAvatarProperty avatarProperty = user.getProperty(KeycloakAvatarProperty.class);
            if (avatarProperty != null) {
                return avatarProperty.getAvatarUrl();
            }
        }
        return null;
    }
}
