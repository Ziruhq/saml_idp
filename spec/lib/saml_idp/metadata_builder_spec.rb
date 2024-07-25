require 'spec_helper'
module SamlIdp
  describe MetadataBuilder do
    it "has a valid fresh" do
      expect(subject.fresh).to_not be_empty
    end

    it "signs valid xml" do
      expect(Saml::XML::Document.parse(subject.signed).valid_signature?(Default::FINGERPRINT)).to be_truthy
    end

    it "includes logout element" do
      subject.configurator.single_logout_service_post_location = 'https://example.com/saml/logout'
      subject.configurator.single_logout_service_redirect_location = 'https://example.com/saml/logout'
      expect(subject.fresh).to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/saml/logout"/>')
      expect(subject.fresh).to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/saml/logout"/>')
    end

    it 'will not includes empty logout endpoint' do
      subject.configurator.single_logout_service_post_location = ''
      subject.configurator.single_logout_service_redirect_location = nil
      expect(subject.fresh).not_to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"')
      expect(subject.fresh).not_to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"')
    end

    it 'will includes sso element' do
      subject.configurator.single_service_post_location = 'https://example.com/saml/sso'
      subject.configurator.single_service_redirect_location = 'https://example.com/saml/sso'
      expect(subject.fresh).to match('<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/saml/sso"/>')
      expect(subject.fresh).to match('<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/saml/sso"/>')
    end

    it 'will not includes empty sso element' do
      subject.configurator.single_service_post_location = ''
      subject.configurator.single_service_redirect_location = nil
      expect(subject.fresh).not_to match('<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"')
      expect(subject.fresh).not_to match('<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"')
    end

    context "technical contact" do
      before do
        subject.configurator.technical_contact.company       = nil
        subject.configurator.technical_contact.given_name    = nil
        subject.configurator.technical_contact.sur_name      = nil
        subject.configurator.technical_contact.telephone     = nil
        subject.configurator.technical_contact.email_address = nil
      end

      it "all fields" do
        subject.configurator.technical_contact.company       = "ACME Corporation"
        subject.configurator.technical_contact.given_name    = "Road"
        subject.configurator.technical_contact.sur_name      = "Runner"
        subject.configurator.technical_contact.telephone     = "1-800-555-5555"
        subject.configurator.technical_contact.email_address = "acme@example.com"
      
        xml = subject.fresh
        expect(xml).to include('<ContactPerson contactType="technical">')
        expect(xml).to include('<Company>ACME Corporation</Company>')
        expect(xml).to include('<GivenName>Road</GivenName>')
        expect(xml).to include('<SurName>Runner</SurName>')
        expect(xml).to include('<EmailAddress>mailto:acme@example.com</EmailAddress>')
        expect(xml).to include('<TelephoneNumber>1-800-555-5555</TelephoneNumber>')
        expect(xml).to include('</ContactPerson>')
      end

      it "no fields" do
        expect(subject.fresh).to include('<ContactPerson contactType="technical">')
        expect(subject.fresh).to include('</ContactPerson>')
        expect(subject.fresh).not_to include('<Company>')
        expect(subject.fresh).not_to include('<GivenName>')
        expect(subject.fresh).not_to include('<SurName>')
        expect(subject.fresh).not_to include('<EmailAddress>')
        expect(subject.fresh).not_to include('<TelephoneNumber>')
      end

      it "just email" do
        subject.configurator.technical_contact.email_address = "acme@example.com"
        
        xml = subject.fresh
        expect(xml).to include('<ContactPerson contactType="technical">')
        expect(xml).to include('<EmailAddress>mailto:acme@example.com</EmailAddress>')
        expect(xml).to include('</ContactPerson>')
        expect(xml).not_to include('<Company>')
        expect(xml).not_to include('<GivenName>')
        expect(xml).not_to include('<SurName>')
        expect(xml).not_to include('<TelephoneNumber>')
      end

    end

    it "includes logout element as HTTP Redirect" do
      subject.configurator.single_logout_service_redirect_location = 'https://example.com/saml/logout'
      expect(subject.fresh).to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/saml/logout"/>')
    end
  end
end
