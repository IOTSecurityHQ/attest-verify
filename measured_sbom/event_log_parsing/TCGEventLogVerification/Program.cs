
using System;
using System.IO;
using System.Text;

namespace TCGEventLogVerification
{
    
    public enum EventType : uint
    {
        EV_PREBOOT_CERT = 0x00000000,
        EV_POST_CODE = 0x00000001,
        EV_UNUSED = 0x00000002,
        EV_NO_ACTION = 0x00000003,
        EV_SEPARATOR = 0x00000004,
        EV_ACTION = 0x00000005,
        EV_EVENT_TAG = 0x00000006,
        EV_S_CRTM_CONTENTS = 0x00000007,
        EV_S_CRTM_VERSION = 0x00000008,
        EV_CPU_MICROCODE = 0x00000009,
        EV_PLATFORM_CONFIG_FLAGS = 0x0000000A,
        EV_TABLE_OF_DEVICES = 0x0000000B,
        EV_COMPACT_HASH = 0x0000000C,
        EV_IPL = 0x0000000D,
        EV_IPL_PARTITION_DATA = 0x0000000E,
        EV_NONHOST_CODE = 0x0000000F,
        EV_NONHOST_CONFIG = 0x00000010,
        EV_NONHOST_INFO = 0x00000011,
        EV_OMIT_BOOT_DEVICE_EVENTS = 0x00000012,
        EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001,
        EV_EFI_VARIABLE_BOOT = 0x80000002,
        EV_EFI_HCRTM_EVENT = 0x80000010,
        EV_EFI_GPT_EVENT = 0x80000006,
        // Add additional event types as needed
    }

    public class UefiGuid
    {
        public uint Data1 { get; set; }
        public ushort Data2 { get; set; }
        public ushort Data3 { get; set; }
        public byte[] Data4 { get; set; } = new byte[8];

        public static UefiGuid ReadFrom(BinaryReader reader)
        {
            return new UefiGuid
            {
                Data1 = reader.ReadUInt32(),
                Data2 = reader.ReadUInt16(),
                Data3 = reader.ReadUInt16(),
                Data4 = reader.ReadBytes(8)
            };
        }

        public override string ToString()
        {
            return $"{Data1:X8}-{Data2:X4}-{Data3:X4}-{BitConverter.ToString(Data4, 0, 2).Replace("-", "")}-{BitConverter.ToString(Data4, 2, 6).Replace("-", "")}";
        }
    }

    public class UefiVariableData
    {
        public UefiGuid VariableName { get; set; }
        public ulong UnicodeNameLength { get; set; }
        public ulong VariableDataLength { get; set; }
        public string UnicodeName { get; set; }
        public byte[] VariableData { get; set; }

        public static UefiVariableData ReadFrom(BinaryReader reader)
        {
            var uefiData = new UefiVariableData
            {
                VariableName = UefiGuid.ReadFrom(reader),
                UnicodeNameLength = reader.ReadUInt64() * 2,    // Need to review specs but there are zeros in middle.
                VariableDataLength = reader.ReadUInt64()
            };

            var nameBytes = reader.ReadBytes((int)uefiData.UnicodeNameLength);
            uefiData.UnicodeName = Encoding.Unicode.GetString(nameBytes);

            uefiData.VariableData = reader.ReadBytes((int)uefiData.VariableDataLength);

            return uefiData;
        }
    }

    public class TcgDigest2
    {
        public ushort AlgorithmId { get; set; }
        public byte[] Digest { get; set; }

        public static TcgDigest2 ReadFrom(BinaryReader reader)
        {
            var digest = new TcgDigest2
            {
                AlgorithmId = reader.ReadUInt16()
            };

            int digestLength = GetDigestLength(digest.AlgorithmId);
            digest.Digest = reader.ReadBytes(digestLength);

            return digest;
        }

        private static int GetDigestLength(ushort algorithmId)
        {
            return algorithmId switch
            {
                0x0004 => 20,    // TPM_ALG_SHA1
                0x000B => 32,    // TPM_ALG_SHA256
                0x000C => 48,    // TPM_ALG_SHA384
                0x000D => 64,    // TPM_ALG_SHA512
                _ => throw new InvalidOperationException($"Unsupported AlgorithmId: {algorithmId}")
            };
        }
    }

    public class TcgEvent2
    {
        public uint EventSize { get; set; }
        public byte[] EventData { get; set; }
        public EventType EventType { get; set; }
        public UefiVariableData UefiVariableData { get; set; }

        public static TcgEvent2 ReadFrom(BinaryReader reader, EventType eventType)
        {
            var event2 = new TcgEvent2
            {
                EventType = eventType,
                EventSize = reader.ReadUInt32()
            };

            event2.EventData = reader.ReadBytes((int)event2.EventSize);
            event2.ParseEventData();

            return event2;
        }


        private void ParseEventData()
     
        {
            switch (EventType)
            {
                case EventType.EV_PREBOOT_CERT:
                    // This event is currently not used; no verification needed.
                    break;

                case EventType.EV_POST_CODE:
                    // Verification logic for EV_POST_CODE
                     {
                    //     // Assume 'rim' is a Dictionary<string, byte[]> containing  RIM entries.
                    //     byte[] expectedDigest;
                    //     if (rim.TryGetValue("POST_Code_Module", out expectedDigest))
                    //     {
                    //         // Compare the event's digests with the expected digest.
                    //         bool matchFound = false;
                    //         foreach (var digest in Digests)
                    //         {
                    //             if (digest.Digest.SequenceEqual(expectedDigest))
                    //             {
                    //                 matchFound = true;
                    //                 break;
                    //             }
                    //         }
                    //         if (matchFound)
                    //         {
                    //             Console.WriteLine("EV_POST_CODE verification succeeded.");
                    //         }
                    //         else
                    //         {
                    //             Console.WriteLine("EV_POST_CODE verification failed: digest mismatch.");
                    //         }
                    //     }
                    //     else
                    //     {
                    //         Console.WriteLine("RIM entry for 'POST_Code_Module' not found.");
                    //     }
                    }
                    break;

                case EventType.EV_S_CRTM_CONTENTS:
                    // Verification logic for EV_S_CRTM_CONTENTS
                    {
                    //     byte[] expectedDigest;
                    //     if (rim.TryGetValue("SRTM_Module", out expectedDigest))
                    //     {
                    //         bool matchFound = false;
                    //         foreach (var digest in Digests)
                    //         {
                    //             if (digest.Digest.SequenceEqual(expectedDigest))
                    //             {
                    //                 matchFound = true;
                    //                 break;
                    //             }
                    //         }
                    //         if (matchFound)
                    //         {
                    //             Console.WriteLine("EV_S_CRTM_CONTENTS verification succeeded.");
                    //         }
                    //         else
                    //         {
                    //             Console.WriteLine("EV_S_CRTM_CONTENTS verification failed: digest mismatch.");
                    //         }
                    //     }
                    //     else
                    //     {
                    //         Console.WriteLine("RIM entry for 'SRTM_Module' not found.");
                    //     }
                    }
                    break;

                case EventType.EV_EFI_VARIABLE_DRIVER_CONFIG:

                case EventType.EV_EFI_VARIABLE_BOOT:
                    // Parse UEFI Variable Data
                    using (var ms = new MemoryStream(EventData))
                    using (var eventReader = new BinaryReader(ms))
                    {
                        UefiVariableData = UefiVariableData.ReadFrom(eventReader);
                    }

                    // Verification logic for EFI Variable events
                    {
                        string variableName = UefiVariableData.UnicodeName.Trim('\0');

                        byte[] expectedDigest;
                        // if (rim.TryGetValue(variableName, out expectedDigest))
                        // {
                        //     bool matchFound = false;
                        //     foreach (var digest in Digests)
                        //     {
                        //         if (digest.Digest.SequenceEqual(expectedDigest))
                        //         {
                        //             matchFound = true;
                        //             break;
                        //         }
                        //     }
                        //     if (matchFound)
                        //     {
                        //         Console.WriteLine($"Verification succeeded for EFI Variable '{variableName}'.");
                        //     }
                        //     else
                        //     {
                        //         Console.WriteLine($"Verification failed for EFI Variable '{variableName}': digest mismatch.");
                        //     }
                        // }
                        // else
                        // {
                        //     Console.WriteLine($"RIM entry for EFI Variable '{variableName}' not found.");
                        // }
                    }
                    break;

                // Handle other event types as needed

                case EventType.EV_EFI_HCRTM_EVENT:
                    {
                    //     byte[] expectedDigest;
                    //     if (rim.TryGetValue("HCRTM_Module", out expectedDigest))
                    //     {
                    //         bool matchFound = false;
                    //         foreach (var digest in Digests)
                    //         {
                    //             if (digest.Digest.SequenceEqual(expectedDigest))
                    //             {
                    //                 matchFound = true;
                    //                 break;
                    //             }
                    //         }
                    //         if (matchFound)
                    //         {
                    //             Console.WriteLine("EV_HC_CRTM_CONTENTS verification succeeded.");
                    //         }
                    //         else
                    //         {
                    //             Console.WriteLine("EV_HC_CRTM_CONTENTS verification failed: digest mismatch.");
                    //         }
                    //     }
                    //     else
                    //     {
                    //         Console.WriteLine("RIM entry for 'HCRTM_Module' not found.");
                    //     }
                     }
                    break;

                default:
                    // Unknown or unhandled event type; no verification.
                    break;
            }
        }
    }

    public class TcgEvent
    {
        public uint PcrIndex { get; set; }
        public uint EventType { get; set; }
        public byte[] Digest { get; set; } = new byte[20];
        public uint EventDataSize { get; set; }
        public byte[] EventData { get; set; }

        public static TcgEvent ReadFrom(BinaryReader reader)
        {
            var tcgEvent = new TcgEvent
            {
                PcrIndex = reader.ReadUInt32(),
                EventType = reader.ReadUInt32()
            };

            tcgEvent.Digest = reader.ReadBytes(20);
            tcgEvent.EventDataSize = reader.ReadUInt32();
            tcgEvent.EventData = reader.ReadBytes((int)tcgEvent.EventDataSize);

            return tcgEvent;
        }
    }

    public class TcgEventHeader2
    {
        public uint PCRIndex { get; set; }
        public EventType EventType { get; set; }
        public uint DigestCount { get; set; }
        public TcgDigest2[] Digests { get; set; }
        public TcgEvent2 Event { get; set; }

        public static TcgEventHeader2 ReadFrom(BinaryReader reader)
        {
            var header = new TcgEventHeader2
            {
                PCRIndex = reader.ReadUInt32(),
                EventType = (EventType)reader.ReadUInt32(),
                DigestCount = reader.ReadUInt32()
            };

            header.Digests = new TcgDigest2[header.DigestCount];
            for (int i = 0; i < header.DigestCount; i++)
            {
                header.Digests[i] = TcgDigest2.ReadFrom(reader);
            }

            header.Event = TcgEvent2.ReadFrom(reader, header.EventType);

            return header;
        }
    }

    class Program
    {    
        static void Main(string[] args)
        {   
         
            string filePath = args.Length > 0 ? args[0] : "measured_sbom/event_log_parsing/TCGEventLogVerification/event-gce-ubuntu-2104-log.bin";

            try
            {
                using (var stream = File.OpenRead(filePath))
                using (var reader = new BinaryReader(stream))
                {
                    // Read the first TCG_EVENT (for TPM 1.2)
                    TcgEvent firstEvent = TcgEvent.ReadFrom(reader);
                    DisplayEvent(firstEvent);

                    // Read subsequent TCG_EVENT_HEADER2 events (for TPM 2.0)
                    while (stream.Position < stream.Length)
                    {
                        TcgEventHeader2 headerEvent = TcgEventHeader2.ReadFrom(reader);
                        DisplayEventHeader2(headerEvent);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }

        static void DisplayEvent(TcgEvent tcgEvent)
        {
            Console.WriteLine("First Event:");
            Console.WriteLine("PCR Index: " + tcgEvent.PcrIndex);
            Console.WriteLine("Event Type: " + tcgEvent.EventType);
            Console.WriteLine("Digest: " + BitConverter.ToString(tcgEvent.Digest));
            Console.WriteLine("Event Data Size: " + tcgEvent.EventDataSize);
            Console.WriteLine("Event Data: " + BitConverter.ToString(tcgEvent.EventData));
            Console.WriteLine("-----------------------------------");
        }

        static void DisplayEventHeader2(TcgEventHeader2 headerEvent)
        {
            Console.WriteLine("Subsequent Event Header:");
            Console.WriteLine("PCR Index: " + headerEvent.PCRIndex);
            Console.WriteLine("Event Type: " + headerEvent.EventType);
            Console.WriteLine("Digest Count: " + headerEvent.DigestCount);

            for (int i = 0; i < headerEvent.Digests.Length; i++)
            {
                Console.WriteLine($"Digest {i + 1} (Algorithm {headerEvent.Digests[i].AlgorithmId}): " + BitConverter.ToString(headerEvent.Digests[i].Digest));
            }

            Console.WriteLine("Event Size: " + headerEvent.Event.EventSize);

            if (headerEvent.Event.EventType == EventType.EV_EFI_VARIABLE_DRIVER_CONFIG && headerEvent.Event.UefiVariableData != null)
            {
                Console.WriteLine("UEFI Variable Data:");
                Console.WriteLine("Variable Name: " + headerEvent.Event.UefiVariableData.VariableName);
                Console.WriteLine("Unicode Name: " + headerEvent.Event.UefiVariableData.UnicodeName);
                Console.WriteLine("Variable Data: " + BitConverter.ToString(headerEvent.Event.UefiVariableData.VariableData));
            }
            else
            {
                Console.WriteLine("Event Data: " + BitConverter.ToString(headerEvent.Event.EventData));
            }

            Console.WriteLine("-----------------------------------");
        }
    }
}