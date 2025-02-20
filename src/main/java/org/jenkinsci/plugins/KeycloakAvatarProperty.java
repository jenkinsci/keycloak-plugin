package org.jenkinsci.plugins;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;

public class KeycloakAvatarProperty extends UserProperty {

    private final AvatarImage avatarImage;

    public KeycloakAvatarProperty(AvatarImage avatarImage) {
        this.avatarImage = avatarImage;
    }

    public String getAvatarUrl() {
        if (isHasAvatar()) {
            return getAvatarImageUrl();
        }
        return null;
    }

    private String getAvatarImageUrl() {
        return avatarImage.url;
    }

    public boolean isHasAvatar() {
        return avatarImage != null && avatarImage.isValid();
    }

    public String getDisplayName() {
        return "Keycloak Avatar";
    }

    public String getIconFileName() {
        return null;
    }

    public String getUrlName() {
        return "keycloak-avatar";
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        @NonNull
        public String getDisplayName() {
            return "Keycloak Avatar";
        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public UserProperty newInstance(User user) {
            return new KeycloakAvatarProperty(null);
        }
    }

    /**
     * Keycloak avatar is the standard picture field on the profile claim.
     */
    public static class AvatarImage {
        private final String url;

        public AvatarImage(String url) {
            this.url = url;
        }

        public boolean isValid() {
            return url != null;
        }
    }
}
