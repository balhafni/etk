from etk.extractors.regex_extractor import RegexExtractor


class TimeExtractor(RegexExtractor):
    """
    **Description**
           This class inherits RegexExtractor and predefines the ip address pattern

    Examples:
        ::

            ip_address_extractor = IPAddressExtractor()
            ip_address_extractor.extract(text=input_doc)
    """
    def __init__(self):
        time_pattern = "\;([\d\:]+)\;"
        RegexExtractor.__init__(self, pattern=time_pattern, extractor_name="time")
