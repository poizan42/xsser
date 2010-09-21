#!/usr/bin/python
# -*- coding: iso-8859-15 -*-

import xml.etree.ElementTree as ET
import datetime

class xml_reporting(object):
    """
    Print results from an attack in an XML fashion
    """
    def __init__(self, xsser):
        # initialize main XSSer
        self.instance = xsser

    def print_xml_results(self, filename):
        root = ET.Element("report")
        hdr = ET.SubElement(root, "header")
        title = ET.SubElement(hdr, "title")
        title.text = "XSSer Security Report: " + str(datetime.datetime.now())
        abstract = ET.SubElement(root, "abstract")
        total_injections = len(self.instance.hash_found) + len(self.instance.hash_notfound)

        if len(self.instance.hash_found) + len(self.instance.hash_notfound) == 0:
            pass 
        injections = ET.SubElement(abstract, "injections")
        total_inj = ET.SubElement(injections, "total")
        failed_inj = ET.SubElement(injections, "failed")
        success_inj = ET.SubElement(injections, "successful")
        accur_inj = ET.SubElement(injections, "accur")

        total_inj_i = len(self.instance.hash_found) + len(self.instance.hash_notfound)

        total_inj.text = str(total_inj_i)
        failed_inj.text = str(len(self.instance.hash_notfound))
        success_inj.text = str(len(self.instance.hash_found))
        accur_inj.text = "%s %%" % (str((len(self.instance.hash_found) * 100) / total_inj_i), )

        if self.instance.options.statistics:
            stats = ET.SubElement(root, "stats")
            test_time = datetime.datetime.now() - self.instance.time
            time_ = ET.SubElement(stats, "duration")
            time_.text = str(test_time)
            total_connections = self.instance.success_connection + self.instance.not_connection + self.instance.forwarded_connection + self.instance.other_connection
            con = ET.SubElement(stats, "connections")
            tcon = ET.SubElement(con, "total")
            tcon.text = str(total_connections)
            okcon = ET.SubElement(con, "ok")
            okcon.text = str(self.instance.success_connection)
            notfound = ET.SubElement(con, "notfound")
            notfound.text = str(self.instance.not_connection)
            forbidden = ET.SubElement(con, "forbidden")
            forbidden.text = str(self.instance.forwarded_connection)
            othercon = ET.SubElement(con, "other")
            othercon.text = str(self.instance.other_connection)
            st_accur = ET.SubElement(con, "accur")
            st_accur.text = "%s %%" % (str((self.instance.success_connection * 100) / total_connections), )
            st_inj = ET.SubElement(stats, "injections")
            st_inj_total = ET.SubElement(st_inj, "total")
            st_inj_total.text = str(total_injections)
            st_vector = ET.SubElement(st_inj, "vectors")
            st_vector.text = str(total_injections - self.instance.other_injections)
            st_special = ET.SubElement(st_inj, "special")
            st_special.text = str(self.instance.other_injections)
            st_success = ET.SubElement(st_inj, "successful")
            st_success.text = str(len(self.instance.hash_found))
            st_failed = ET.SubElement(st_inj, "failed")
            st_failed.text = str(len(self.instance.hash_notfound))
            st_accur = ET.SubElement(st_inj, "accur")
            st_accur.text = "%s %%" % (str(((len(self.instance.hash_found) * 100) / total_injections)),)

        results = ET.SubElement(root, "results")
        for line in self.instance.hash_found:
            attack = ET.SubElement(results, "attack")
            url_ = ET.SubElement(attack, "injection")
            url_.text = line[0]
            attack_url = self.instance.apply_postprocessing(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
            if not attack_url == line[0]:
                aurl = ET.SubElement(attack, "finalattack")
                aurl.text = attack_url
            browsers = ET.SubElement(attack, "browsers")
            browsers.text = line[1]
            method = ET.SubElement(attack, "method")
            method.text = line[2]

        if not self.instance.hash_found:
            msg = ET.SubElement(results, "message")
            msg.text = "Failed injection: "+ str(''.join([u[0] for u in self.instance.hash_notfound])) 
        tree = ET.ElementTree(root)
        tree.write(filename)

