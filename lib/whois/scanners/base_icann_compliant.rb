require_relative 'base'

module Whois
  module Scanners

    # Scanner for the Icann Compliant-based records.
    class BaseIcannCompliant < Base

      self.tokenizers += [
          :skip_head,
          :scan_available,
          :scan_throttled,
          :skip_empty_line,
          :skip_blank_line,
          :scan_keyvalue,
          #:scan_notice,
          :scan_disclaimer,
          :skip_end,
      ]

      tokenizer :scan_available do
        if settings[:pattern_available] && @input.skip_until(settings[:pattern_available])
          @ast['status:available'] = true
        end
      end

      tokenizer :scan_throttled do
        if settings[:pattern_throttled] && @input.skip_until(settings[:pattern_throttled])
          @ast['response:throttled'] = true
        end
      end

      tokenizer :skip_head do
        if @input.skip_until(/Domain Name:/)
          @input.scan(/\s?(.+)\n/)
          @ast["Domain Name"] = @input[1].strip
        end
      end

      # tokenizer :scan_notice do
      #   if settings[:pattern_notice] && @input.match?(settings[:pattern_notice])
      #     @ast["field:notice"] = _scan_lines_to_array(/(.+)\n/).join(" ")
      #   end
      # end

      tokenizer :scan_disclaimer do
        if settings[:pattern_disclaimer] && @input.match?(settings[:pattern_disclaimer])
          @ast["field:disclaimer"] = _scan_lines_to_array(/^(.+)\n/).join(" ")
        end
      end

      tokenizer :skip_end do
        @input.terminate
      end

    end

  end
end
