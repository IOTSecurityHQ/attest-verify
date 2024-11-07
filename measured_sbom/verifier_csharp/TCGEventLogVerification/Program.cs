using System;
using System.IO;

namespace TCGEventLogVerification
{
    using System;
using System.IO;


using System;
using System.IO;

public class TcgEventHeader2
{
    public uint PCRIndex { get; set; }
    public uint EventType { get; set; }
    public uint DigestCount { get; set; }
    public TcgDigest2[] Digests { get; set; }
    public TcgEvent2 Event { get; set; }

    // Constructor to read and initialize from BinaryReader
    public static TcgEventHeader2 ReadFrom(BinaryReader reader)
    {
        var header = new TcgEventHeader2
        {
            PCRIndex = reader.ReadUInt32(),
            EventType = reader.ReadUInt32(),
            DigestCount = reader.ReadUInt32()
        };

        // Read the array of Digests based on DigestCount
        header.Digests = new TcgDigest2[header.DigestCount];
        for (int i = 0; i < header.DigestCount; i++)
        {
            header.Digests[i] = TcgDigest2.ReadFrom(reader);
        }

        // Read the TCG_EVENT2 structure after the digests
        header.Event = TcgEvent2.ReadFrom(reader);

        return header;
    }
}

public class TcgDigest2
{
    public ushort AlgorithmId { get; set; }
    public byte[] Digest { get; set; }

    // Constructor to read and initialize from BinaryReader
    public static TcgDigest2 ReadFrom(BinaryReader reader)
    {
        var digest = new TcgDigest2
        {
            AlgorithmId = reader.ReadUInt16()
        };

        // Determine digest length based on AlgorithmId
        int digestLength = GetDigestLength(digest.AlgorithmId);
        digest.Digest = reader.ReadBytes(digestLength);

        return digest;
    }

    // Helper method to get the digest length based on AlgorithmId
    private static int GetDigestLength(ushort algorithmId)
    {
        return algorithmId switch
        {
            4 => 20,             // SHA-1: 20 bytes
            11 => 32,            // SHA-256: 32 bytes
            12 => 48,       // SHA-384: 48 bytes
            _ => throw new InvalidOperationException($"Unsupported AlgorithmId: {algorithmId}")
        };
    }
}

public class TcgEvent2
{
    public uint EventSize { get; set; }
    public byte[] EventData { get; set; }

    // Constructor to read and initialize from BinaryReader
    public static TcgEvent2 ReadFrom(BinaryReader reader)
    {
        var event2 = new TcgEvent2
        {
            EventSize = reader.ReadUInt32()
        };

        // Read the Event data based on EventSize
        event2.EventData = reader.ReadBytes((int)event2.EventSize);
        
        return event2;
    }
}
public class TcgEvent
{
    public uint PcrIndex { get; set; }
    public uint EventType { get; set; }
    public byte[] Digest { get; set; } = new byte[20];
    public uint EventDataSize { get; set; }
    public byte[] EventData { get; set; }

    // Constructor to read and initialize from BinaryReader
    public static TcgEvent ReadFrom(BinaryReader reader)
    {
        var tcgEvent = new TcgEvent
        {
            PcrIndex = reader.ReadUInt32(),
            EventType = reader.ReadUInt32()
        };

        // Read the 20-byte digest
        tcgEvent.Digest = reader.ReadBytes(20);

        // Read EventDataSize and use it to read the EventData array
        tcgEvent.EventDataSize = reader.ReadUInt32();
        tcgEvent.EventData = reader.ReadBytes((int)tcgEvent.EventDataSize);

        return tcgEvent;
    }
}
   class Program
{
    static void Main(string[] args)
    {
        string filePath = "event-gce-ubuntu-2104-log.bin";

        try
        {
            using (var stream = File.OpenRead(filePath))
            using (var reader = new BinaryReader(stream))
            {
                // Read the first TCG_EVENT
                TcgEvent firstEvent = TcgEvent.ReadFrom(reader);
                DisplayEvent(firstEvent);

                // Read subsequent TCG_EVENT_HEADER2 events
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
            Console.WriteLine($"Digest {i + 1}: " + BitConverter.ToString(headerEvent.Digests[i].Digest));
        }

        Console.WriteLine("Event Size: " + headerEvent.Event.EventSize);
        Console.WriteLine("Event Data: " + BitConverter.ToString(headerEvent.Event.EventData));
        Console.WriteLine("-----------------------------------");
    }
}
}