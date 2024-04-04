#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_iisse'


module Whois
  class Parsers

    # Base parser for IIS.se servers.
    #
    # @abstract
    class BaseIisse < Base
      include Scanners::Scannable

      self.scanner = Scanners::BaseIisse


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("domain")
      end

      property_not_supported :domain_id


      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("created") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("expires") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("modified") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("registrar") { |name| Parser::Registrar.new(name: name) unless name == "-" }
      end


      property_supported :registrant_contacts do
        build_contact(Parser::Contact::TYPE_REGISTRANT, node("holder"))
      end

      property_supported :admin_contacts do
        build_contact(Parser::Contact::TYPE_ADMINISTRATIVE, node("admin-c"))
      end

      property_supported :technical_contacts do
        build_contact(Parser::Contact::TYPE_TECHNICAL, node("tech-c"))
      end


      # nserver:  ns2.loopia.se
      # nserver:  ns2.loopia.se 93.188.0.21
      #
      property_supported :nameservers do
        node("nserver") do |values|
          Array.wrap(values).map do |line|
            name, ipv4 = line.split(/\s+/)
            Parser::Nameserver.new(name: name, ipv4: ipv4)
          end
        end
      end


      private

      def build_contact(type, id)
        return if id.nil? || id == "-"

        Parser::Contact.new(
            type: type,
            id: id
        )
      end

    end

  end
end
