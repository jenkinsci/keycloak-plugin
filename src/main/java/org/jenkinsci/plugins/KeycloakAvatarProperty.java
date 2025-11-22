package org.jenkinsci.plugins;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import jenkins.security.csp.AvatarContributor;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;

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
    @SuppressRestrictedWarnings(AvatarContributor.class)
    public static class AvatarImage {
        private final String url;

        public AvatarImage(String url) {
            this.url = url;
            AvatarContributor.allow(url);
        }

        public boolean isValid() {
            return url != null;
        }

        private Object readResolve() {
            AvatarContributor.allow(url);
            return this;
        }
    }
}
