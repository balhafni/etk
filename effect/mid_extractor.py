from etk.extractors.regex_extractor import RegexExtractor


class MIDExtractor(RegexExtractor):
    """
    **Description**
           This class inherits RegexExtractor and predefines the ip address pattern

    Examples:
        ::

            ip_address_extractor = IPAddressExtractor()
            ip_address_extractor.extract(text=input_doc)
    """
    def __init__(self):
        mid_pattern = "(?:.+?(?=MID))?MID\s((\d+)?)"
        RegexExtractor.__init__(self, pattern=mid_pattern, extractor_name="MID")
