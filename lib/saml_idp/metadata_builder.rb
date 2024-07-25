require 'saml_idp/name_id_formatter'
require 'saml_idp/attribute_decorator'
require 'saml_idp/algorithmable'
require 'saml_idp/signable'

module SamlIdp
  class MetadataBuilder
    include Algorithmable
    include Signable
    attr_accessor :configurator

    def initialize(configurator = SamlIdp.config)
      self.configurator = configurator
    end

    def fresh
      builder = Builder::XmlMarkup.new(indent: 2)
      generated_reference_id do
        builder.EntityDescriptor ID: reference_string,
          xmlns: Saml::XML::Namespaces::METADATA,
          "xmlns:md" => Saml::XML::Namespaces::METADATA,
          "xmlns:ds" => Saml::XML::Namespaces::SIGNATURE,
          entityID: entity_id do |entity|
            sign entity

            entity.IDPSSODescriptor protocolSupportEnumeration: protocol_enumeration,
                                    WantAuthnRequestsSigned: signed_auth_requests? do |descriptor|
              build_key_descriptor descriptor
              build_name_id_formats descriptor
              build_single_sign_on_services descriptor
              build_single_logout_services descriptor
              build_attribute descriptor
            end

            build_contact entity
          end
      end
    end
    alias_method :raw, :fresh

    private

    def build_key_descriptor(el)
      el.KeyDescriptor use: "signing" do |key_descriptor|
        key_descriptor.KeyInfo xmlns: Saml::XML::Namespaces::SIGNATURE do |key_info|
          key_info.X509Data do |x509|
            x509.X509Certificate x509_certificate
          end
        end
      end
    end

    def build_name_id_formats(el)
      name_id_formats.each do |format|
        el.NameIDFormat format
      end
    end

    def build_single_sign_on_services(el)
      build_endpoint(el, [
        { tag: 'SingleSignOnService', url: single_service_post_location, bind: 'HTTP-POST' },
        { tag: 'SingleSignOnService', url: single_service_redirect_location, bind: 'HTTP-Redirect' }
      ])
    end

    def build_single_logout_services(el)
      build_endpoint(el, [
        { tag: 'SingleLogoutService', url: single_logout_service_post_location, bind: 'HTTP-POST' },
        { tag: 'SingleLogoutService', url: single_logout_service_redirect_location, bind: 'HTTP-Redirect' }
      ])
    end

    def build_endpoint(el, end_points)
      end_points.each do |ep|
        next unless ep[:url].present?

        el.tag! ep[:tag],
          Binding: "urn:oasis:names:tc:SAML:2.0:bindings:#{ep[:bind]}",
          Location: ep[:url]
      end
    end

    def build_attribute(el)
      attributes.each do |attribute|
        el.Attribute NameFormat: attribute.name_format,
                     Name: attribute.name,
                     FriendlyName: attribute.friendly_name do |attr|
          attribute.values.each do |value|
            attr.AttributeValue value
          end
        end
      end
    end

    def build_contact(el)
      el.ContactPerson contactType: "technical" do |contact|
        contact.Company         technical_contact.company         if technical_contact.company
        contact.GivenName       technical_contact.given_name      if technical_contact.given_name
        contact.SurName         technical_contact.sur_name        if technical_contact.sur_name
        contact.EmailAddress    technical_contact.mail_to_string  if technical_contact.mail_to_string
        contact.TelephoneNumber technical_contact.telephone       if technical_contact.telephone
      end
    end

    def reference_string
      "_#{reference_id}"
    end

    def entity_id
      configurator.entity_id.presence || configurator.base_saml_location
    end

    def protocol_enumeration
      Saml::XML::Namespaces::PROTOCOL
    end

    def attributes
      @attributes ||= configurator.attributes.inject([]) do |list, (key, opts)|
        opts[:friendly_name] = key
        list << AttributeDecorator.new(opts)
        list
      end
    end

    def name_id_formats
      @name_id_formats ||= NameIdFormatter.new(configurator.name_id.formats).all
    end

    def signed_auth_requests?
      !!configurator.signed_auth_requests
    end

    def raw_algorithm
      configurator.algorithm
    end

    def x509_certificate
      SamlIdp.config.x509_certificate
      .to_s
      .gsub(/-----BEGIN CERTIFICATE-----/,"")
      .gsub(/-----END CERTIFICATE-----/,"")
      .gsub(/\n/, "")
    end

    %w[
      single_service_post_location
      single_service_redirect_location
      single_logout_service_post_location
      single_logout_service_redirect_location
      technical_contact
    ].each do |delegatable|
      define_method(delegatable) do
        configurator.public_send delegatable
      end
    end
  end
end