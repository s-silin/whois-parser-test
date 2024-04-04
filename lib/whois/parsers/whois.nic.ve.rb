#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    #
    # = whois.nic.ve parser
    #
    # Parser for the whois.nic.ve server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicVe < Base

      property_supported :status do
        if content_for_scanner =~ /Estatus del dominio: (.+?)\n/
          case $1.downcase
            when "activo"
              :registered
            when "suspendido"
              :inactive
            else
              Whois::Parser.bug!(ParserError, "Unknown status `#{$1}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /No match for "(.+?)"/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Fecha de Creac.+?: (.+?)\n/
          parse_time($1)
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Ultima Actualizac.+?: (.+?)\n/
          parse_time($1)
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Fecha de Vencimiento: (.+?)\n/
          parse_time($1)
        end
      end

      property_supported :nameservers do
        if content_for_scanner =~ /Servidor\(es\) de Nombres de Dominio:\n\n((.+\n)+)\n/
          $1.scan(/-\s(.*?)\n/).flatten.map do |name|
            Parser::Nameserver.new(:name => name)
          end
        end
      end

      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts
      property_not_supported :registrar

      # NEWPROPERTY
      # def suspended?
      # end
    end
  end
end
