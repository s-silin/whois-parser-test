require 'strscan'

module Whois
  module Scanners

    # The Scannable module tries to emulate a super-simple Abstract Syntax Tree structure
    # including method for accessing ast nodes.
    #
    # == Usage
    #
    # Include the Scannable module and set the `self.scanner` value.
    #
    #   class ParserFoo
    #     include Scannable
    #
    #     self.scanner = ScannerFoo
    #   end
    #
    # Now you can access the AST using the <tt>node</tt> method.
    #
    #   node "created_on"
    #   # => "2009-12-12"
    #
    #   node? "created_on"
    #   # => true
    #
    #   node? "created_at"
    #   # => false
    #
    module Scannable

      def self.included(base)
        base.class_attribute :scanner
      end

      def node(key)
        key = key.find { |k| ast.key?(k) } if key.is_a?(Array)

        if block_given?
          value = ast[key]
          value = yield(value) unless value.nil?
          value
        else
          ast[key]
        end
      end

      def node?(key)
        !ast[key].nil?
      end

      def parse
        scanner  = self.scanner.is_a?(Array) ? self.scanner.first : self.scanner
        settings = self.scanner.is_a?(Array) ? self.scanner.last  : {}
        scanner.new(settings).parse(content_for_scanner)
      end

      private

      def ast
        @ast ||= parse
      end

    end

  end
end
