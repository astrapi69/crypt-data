package de.alpharogroup.crypto.certificate;

public class CertificateAttributes {
    private String commonName;
    private String organisation;
    private String organisationUnit;
    private String countryCode;
    private String state;
    private String location;

    public CertificateAttributes(String commonName, String organisation, String organisationUnit, String countryCode, String state, String location) {
        this.commonName = commonName;
        this.organisation = organisation;
        this.organisationUnit = organisationUnit;
        this.countryCode = countryCode;
        this.state = state;
        this.location = location;
    }

    public CertificateAttributes() {
    }

    protected CertificateAttributes(CertificateAttributesBuilder<?, ?> b) {
        this.commonName = b.commonName;
        this.organisation = b.organisation;
        this.organisationUnit = b.organisationUnit;
        this.countryCode = b.countryCode;
        this.state = b.state;
        this.location = b.location;
    }

    public static CertificateAttributesBuilder<?, ?> builder() {
        return new CertificateAttributesBuilderImpl();
    }

    public String toRepresentableString(){
        StringBuilder stringBuilder = new StringBuilder();
        if(setCertificateValue(stringBuilder, "C", countryCode)){
            stringBuilder.append(", ");
        }
        if(setCertificateValue(stringBuilder, "ST", state)){
            stringBuilder.append(", ");
        }
        if(setCertificateValue(stringBuilder, "L", location)){
            stringBuilder.append(", ");
        }
        if(setCertificateValue(stringBuilder, "O", organisation)){
            stringBuilder.append(", ");
        }
        if(setCertificateValue(stringBuilder, "OU", organisationUnit)){
            stringBuilder.append(", ");
        }
        if(setCertificateValue(stringBuilder, "CN", commonName)){
            stringBuilder.append(", ");
        }
        String result = stringBuilder.toString();
        if(result.endsWith(", ")){
            result = result.substring(0, result.lastIndexOf(", "));
        }
        return result;
    }

    private boolean setCertificateValue(StringBuilder stringBuilder, String key, String certificateValue) {
        if(certificateValue!=null && !certificateValue.isEmpty()){
            stringBuilder.append(key).append("=").append(certificateValue);
            return true;
        }
        return false;
    }

    public String getCommonName() {
        return this.commonName;
    }

    public String getOrganisation() {
        return this.organisation;
    }

    public String getOrganisationUnit() {
        return this.organisationUnit;
    }

    public String getCountryCode() {
        return this.countryCode;
    }

    public String getState() {
        return this.state;
    }

    public String getLocation() {
        return this.location;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public void setOrganisation(String organisation) {
        this.organisation = organisation;
    }

    public void setOrganisationUnit(String organisationUnit) {
        this.organisationUnit = organisationUnit;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    public void setState(String state) {
        this.state = state;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof CertificateAttributes)) return false;
        final CertificateAttributes other = (CertificateAttributes) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$commonName = this.getCommonName();
        final Object other$commonName = other.getCommonName();
        if (this$commonName == null ? other$commonName != null : !this$commonName.equals(other$commonName))
            return false;
        final Object this$organisation = this.getOrganisation();
        final Object other$organisation = other.getOrganisation();
        if (this$organisation == null ? other$organisation != null : !this$organisation.equals(other$organisation))
            return false;
        final Object this$organisationUnit = this.getOrganisationUnit();
        final Object other$organisationUnit = other.getOrganisationUnit();
        if (this$organisationUnit == null ? other$organisationUnit != null : !this$organisationUnit.equals(other$organisationUnit))
            return false;
        final Object this$countryCode = this.getCountryCode();
        final Object other$countryCode = other.getCountryCode();
        if (this$countryCode == null ? other$countryCode != null : !this$countryCode.equals(other$countryCode))
            return false;
        final Object this$state = this.getState();
        final Object other$state = other.getState();
        if (this$state == null ? other$state != null : !this$state.equals(other$state)) return false;
        final Object this$location = this.getLocation();
        final Object other$location = other.getLocation();
        if (this$location == null ? other$location != null : !this$location.equals(other$location)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof CertificateAttributes;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $commonName = this.getCommonName();
        result = result * PRIME + ($commonName == null ? 43 : $commonName.hashCode());
        final Object $organisation = this.getOrganisation();
        result = result * PRIME + ($organisation == null ? 43 : $organisation.hashCode());
        final Object $organisationUnit = this.getOrganisationUnit();
        result = result * PRIME + ($organisationUnit == null ? 43 : $organisationUnit.hashCode());
        final Object $countryCode = this.getCountryCode();
        result = result * PRIME + ($countryCode == null ? 43 : $countryCode.hashCode());
        final Object $state = this.getState();
        result = result * PRIME + ($state == null ? 43 : $state.hashCode());
        final Object $location = this.getLocation();
        result = result * PRIME + ($location == null ? 43 : $location.hashCode());
        return result;
    }

    public String toString() {
        return "CertificateAttributes(commonName=" + this.getCommonName() + ", organisation=" + this.getOrganisation() + ", organisationUnit=" + this.getOrganisationUnit() + ", countryCode=" + this.getCountryCode() + ", state=" + this.getState() + ", location=" + this.getLocation() + ")";
    }

    public CertificateAttributesBuilder<?, ?> toBuilder() {
        return new CertificateAttributesBuilderImpl().$fillValuesFrom(this);
    }

    public static abstract class CertificateAttributesBuilder<C extends CertificateAttributes, B extends CertificateAttributes.CertificateAttributesBuilder<C, B>> {
        private String commonName;
        private String organisation;
        private String organisationUnit;
        private String countryCode;
        private String state;
        private String location;

        private static void $fillValuesFromInstanceIntoBuilder(CertificateAttributes instance, CertificateAttributes.CertificateAttributesBuilder<?, ?> b) {
            b.commonName(instance.commonName);
            b.organisation(instance.organisation);
            b.organisationUnit(instance.organisationUnit);
            b.countryCode(instance.countryCode);
            b.state(instance.state);
            b.location(instance.location);
        }

        public B commonName(String commonName) {
            this.commonName = commonName;
            return self();
        }

        public B organisation(String organisation) {
            this.organisation = organisation;
            return self();
        }

        public B organisationUnit(String organisationUnit) {
            this.organisationUnit = organisationUnit;
            return self();
        }

        public B countryCode(String countryCode) {
            this.countryCode = countryCode;
            return self();
        }

        public B state(String state) {
            this.state = state;
            return self();
        }

        public B location(String location) {
            this.location = location;
            return self();
        }

        protected B $fillValuesFrom(C instance) {
            CertificateAttributesBuilder.$fillValuesFromInstanceIntoBuilder(instance, this);
            return self();
        }

        protected abstract B self();

        public abstract C build();

        public String toString() {
            return "CertificateAttributes.CertificateAttributesBuilder(commonName=" + this.commonName + ", organisation=" + this.organisation + ", organisationUnit=" + this.organisationUnit + ", countryCode=" + this.countryCode + ", state=" + this.state + ", location=" + this.location + ")";
        }
    }

    private static final class CertificateAttributesBuilderImpl extends CertificateAttributesBuilder<CertificateAttributes, CertificateAttributesBuilderImpl> {
        private CertificateAttributesBuilderImpl() {
        }

        protected CertificateAttributes.CertificateAttributesBuilderImpl self() {
            return this;
        }

        public CertificateAttributes build() {
            return new CertificateAttributes(this);
        }
    }
}
