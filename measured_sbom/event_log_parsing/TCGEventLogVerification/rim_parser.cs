using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

public class RIMParser
{
    public static Dictionary<string, byte[]> ParseCombinedRIM(string rimXmlContent)
    {
        var rimDictionary = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

        XmlDocument xmlDoc = new XmlDocument();

        // Disable DTD processing to prevent XXE attacks
        xmlDoc.XmlResolver = null;

        // Load the XML content
        xmlDoc.LoadXml(rimXmlContent);

        // Handle XML namespaces
        XmlNamespaceManager nsmgr = new XmlNamespaceManager(xmlDoc.NameTable);
        nsmgr.AddNamespace("ns", "http://standards.iso.org/iso/19770/-2/2015/schema.xsd");

        // Select all SoftwareIdentity nodes under rimroot
        XmlNodeList softwareIdentityNodes = xmlDoc.SelectNodes("/ns:rimroot/ns:SoftwareIdentity", nsmgr);

        foreach (XmlNode softwareIdentityNode in softwareIdentityNodes)
        {
            // Parse File elements within this SoftwareIdentity
            XmlNodeList fileNodes = softwareIdentityNode.SelectNodes(".//ns:Payload/ns:Directory/ns:File", nsmgr);
            foreach (XmlNode fileNode in fileNodes)
            {
                string name = fileNode.Attributes["name"]?.Value;
                string hash = fileNode.Attributes["SHA256:hash"]?.Value;

                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(hash))
                {
                    byte[] hashBytes = HexStringToByteArray(hash);
                    rimDictionary[name] = hashBytes;
                }
            }

            // Parse Variable elements within this SoftwareIdentity
            XmlNodeList variableNodes = softwareIdentityNode.SelectNodes(".//ns:Variables/ns:Variable", nsmgr);
            foreach (XmlNode variableNode in variableNodes)
            {
                string name = variableNode.Attributes["name"]?.Value;
                string hash = variableNode.Attributes["SHA256:hash"]?.Value;

                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(hash))
                {
                    byte[] hashBytes = HexStringToByteArray(hash);
                    rimDictionary[name] = hashBytes;
                }
            }
        }

        return rimDictionary;
    }

    // Helper method to convert hex string to byte array
    private static byte[] HexStringToByteArray(string hex)
    {
        hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", ""); // Remove any whitespace
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Invalid length of the hex string.");

        byte[] bytes = new byte[hex.Length / 2];

        for (int i = 0; i < hex.Length; i += 2)
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

        return bytes;
    }
}