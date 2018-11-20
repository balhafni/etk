from etk.etk import ETK
from etk.knowledge_graph.schema import KGSchema
from etk.extractors.glossary_extractor import GlossaryExtractor
from etk.etk_module import ETKModule
from etk.knowledge_graph.node import URI, BNode, Literal
from etk.knowledge_graph.subject import Subject
from ip_extractor import IPAddressExtractor
from mid_extractor import MIDExtractor
from subject_extractor import SubjectExtractor
from loglevel_extractor import LoglevelExtractor
from date_extractor import DateExtractor
from time_extractor import TimeExtractor
from spam_res_extractor import SpamResExtractor
from attachment_extractor import AttachmentExtractor
from spam_engine_extractor import SpamEngineExtractor
from etk.extractors.date_extractor import DateExtractor as etk_date
from etk.document import Document
import json, time

class RegexETKModule(ETKModule):
    """
    Abstract class for extraction module
    """
    def __init__(self, etk):
        ETKModule.__init__(self, etk)
        # bae = BitcoinAddressExtractor()
        # ce = CVEExtractor()
        # che = CryptographicHashExtractor()
        # he = HostnameExtractor()
        ip = IPAddressExtractor()
        mid = MIDExtractor()
        subject = SubjectExtractor()
        loglevel = LoglevelExtractor()
        date = DateExtractor()
        time = TimeExtractor()
        spam_engine = SpamEngineExtractor()
        spam_res = SpamResExtractor()
        attachment = AttachmentExtractor()
        self.date_extractor = etk_date(self.etk, 'log_date_parser')
        # ue = URLExtractor(True)
        self.e_list = [date, time, ip, loglevel, mid, subject, spam_engine, spam_res, attachment]

    def process_document(self, doc):
        """
        Add your code for processing the document
        """
        data = []
        newdocs = list()
        # Bind all your prefixes at here
        # None is default namespace

        doc.kg.bind(None, 'http://isi.edu/default-ns/')
        with open(doc.cdr_document.get("raw_content_path"), "r") as f_in:
            data = f_in.readlines()

        count = 1
        for log in data:
            final_res = []
            sample_input = {
                "target_text": log.strip()
            }
            doc_sample = etk.create_document(sample_input)
            segment = doc_sample.select_segments("target_text")[0]

            # print(segment)
            for e in self.e_list:
                res = doc.extract(e, segment)
                final_res.append(res)

            log_line = segment.value
            mid = ''
            subject = ''
            spam_res = ''
            spam_engine = ''
            attachment = ''
            if final_res[4]:
                mid = final_res[4][0].value
            if final_res[5]:
                subject = final_res[5][0].value
            if final_res[6]:
                spam_engine = final_res[6][0].value
            if final_res[7]:
                spam_res = final_res[7][0].value
            if final_res[8]:
                attachment = final_res[8][0].value


            js = {'log_text':log_line,'date':final_res[0][0].value,'time':final_res[1][0].value,'ip':final_res[2][0].value,
                  'log_level': final_res[3][0].value,'mid':mid,'subject':subject,'spam_engine':spam_engine,'spam_results':spam_res,'attachment':attachment}

            # descriptions = doc.select_segments("projects[*].description")
            # names = doc.select_segments("projects[*].name")
            # projects = doc.select_segments("projects[*]")
            document = Document(self.etk, cdr_document=js, mime_type='json', url='')

            # print(log)
            #TODO, add the message id as a URI in the triple and clean the data as Pedro said!


            triple = Subject(URI("LogLine"+str(count)))
            triple.add_property(URI("rdf:type"), URI("LogData"))

            log_line = Subject(BNode())
            log_line.add_property(URI("rdf:type"), URI("LogText"))
            log_line.add_property(URI("text"), Literal(document.cdr_document.get("log_text")))
            triple.add_property(URI("text"), log_line)

            ip = Subject(BNode())
            ip.add_property(URI("rdf:type"), URI("IPAddress"))
            ip.add_property(URI("ip"), Literal(document.cdr_document.get("ip")))
            triple.add_property(URI("IP"),ip)

            date = Subject(BNode())
            date.add_property(URI("rdf:type"), URI("Date"))
            #let's format the date into ISO before adding it
            unformatted_date = document.cdr_document.get('date', 0)
            if unformatted_date != 0:
                log_date = unformatted_date.split('.')
                iso_date = self.date_extractor.extract('{}-{}-{}'.format(log_date[2], log_date[1], log_date[0]))
                # print(extractables)
                # date.add_property(URI("date"), Literal(document.cdr_document.get("date")))
                date.add_property(URI("date"), Literal(iso_date[0].value +"T"+document.cdr_document.get("time")))
                triple.add_property(URI("date"), date)

            time = Subject(BNode())
            time.add_property(URI("rdf:type"), URI("Time"))
            time.add_property(URI("time"), Literal(document.cdr_document.get("time")))
            triple.add_property(URI("time"), time)

            log_level = Subject(BNode())
            log_level.add_property(URI("rdf:type"), URI("LogLevel"))
            log_level.add_property(URI("level"), Literal(document.cdr_document.get("log_level")))
            triple.add_property(URI("level"), log_level)

            if document.cdr_document.get("mid"):
                msg_id = Subject(BNode())
                msg_id.add_property(URI("rdf:type"), URI("MID"))
                msg_id.add_property(URI("message_id"), Literal(document.cdr_document.get("mid")))
                triple.add_property(URI("message_id"), msg_id)

            if document.cdr_document.get("subject"):
                subject = Subject(BNode())
                subject.add_property(URI("rdf:type"), URI("Subject"))
                subject.add_property(URI("subject"), Literal(document.cdr_document.get("subject")))
                triple.add_property(URI("subject"), subject)

            if document.cdr_document.get("spam_engine"):
                spam_engine = Subject(BNode())
                spam_engine.add_property(URI("rdf:type"), URI("SpamEngine"))
                spam_engine.add_property(URI("engine"), Literal(document.cdr_document.get("spam_engine")))
                triple.add_property(URI("engine"), spam_engine)

            if document.cdr_document.get("spam_results"):
                spam_result = Subject(BNode())
                spam_result.add_property(URI("rdf:type"), URI("SpamFilterResult"))
                spam_result.add_property(URI("result"), Literal(document.cdr_document.get("spam_results")))
                triple.add_property(URI("result"), spam_result)

            if document.cdr_document.get("attachment"):
                attachment = Subject(BNode())
                attachment.add_property(URI("rdf:type"), URI("Attachment"))
                attachment.add_property(URI("attached_file"), Literal(document.cdr_document.get("attachment")))
                triple.add_property(URI("attached_file"), attachment)


            # developers = doc.extract(self.name_extractor, d)
            # p.store(developers, "members")
            # for developer in developers:
            #     developer_t = Subject(BNode())
            #     developer_t.add_property(URI("rdf:type"), URI("Developer"))
            #     developer_t.add_property(URI("name"), Literal(developer.value))
            #     triple.add_property(URI("developer"), developer_t)
            count = count + 1
            doc.kg.add_subject(triple)
            # break

        return list()


if __name__ == "__main__":
    # sample_input = {
    #     "projects": [
    #         {
    #             "name": "etk",
    #             "description": "version 2 of etk, implemented by Runqi Shao, Dongyu Li, Sylvia lin, Amandeep and "
    #                            "others."
    #         },
    #         {
    #             "name": "rltk",
    #             "description": "record linkage toolkit, implemented by Pedro, Mayank, Yixiang and several students."
    #         }
    #     ]
    # }
    f = open("res.txt", "w")
    ontology = """
    @prefix : <http://isi.edu/alhafni-rule-set#> .
    @prefix owl: <http://www.w3.org/2002/07/owl#> .
    @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
    @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
        """
    js = dict()
    js['raw_content_path'] = "logs.txt"
    # js['raw_content_path'] = "/Users/alhafni/Desktop/ironport_logs/ironport.log.2018-08-20"
    js['dataset'] = "logs"

    kg_schema = KGSchema()
    kg_schema.add_schema(ontology, 'ttl')
    etk = ETK(kg_schema=kg_schema, modules=RegexETKModule)
    doc = Document(etk, cdr_document=js, mime_type='json', url='',doc_id="http://isi.edu/default-ns/projects")
    docs = etk.process_ems(doc)


    print(docs[0].kg.serialize('ttl'))
    print(docs[0].kg.serialize('nt'))
    print(docs[0].kg._resolve_uri.cache_info())
    f.write(docs[0].kg.serialize('ttl'))
    f.write(docs[0].kg.serialize('nt'))
    # f.write(docs[0].kg._resolve_uri.cache_info())