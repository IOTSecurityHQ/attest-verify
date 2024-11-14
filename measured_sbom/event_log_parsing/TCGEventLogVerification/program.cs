using TCGEventLogVerification;

class TestApplication
{
    static void Main(string[] args)
    {
        string filePath = "event-gce-ubuntu-2104-log.bin";
        TcgEventLogParser.ParseEventLog(filePath);
    }
}