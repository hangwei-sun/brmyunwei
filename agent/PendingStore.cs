using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;

namespace MonitoringPlatform.Agent
{
    internal sealed class PendingStore
    {
        private readonly string _directory;
        private readonly int _capacity;
        private readonly string _sequencePath;

        public PendingStore(string dataDirectory, int capacity)
        {
            _directory = Path.Combine(dataDirectory, "pending");
            _capacity = capacity;
            _sequencePath = Path.Combine(dataDirectory, "sequence.txt");
            Directory.CreateDirectory(_directory);
        }

        public long NextSequence()
        {
            long current = 0;
            if (File.Exists(_sequencePath)) long.TryParse(File.ReadAllText(_sequencePath).Trim(), out current);
            if (current == long.MaxValue) throw new InvalidOperationException("Agent sequence is exhausted; re-enroll the agent before continuing.");
            var next = current + 1;
            WriteAtomically(_sequencePath, System.Text.Encoding.ASCII.GetBytes(next.ToString()));
            return next;
        }

        public void Enqueue(TelemetrySample sample)
        {
            var path = Path.Combine(_directory, sample.Sequence.ToString("D20") + ".json");
            using (var memory = new MemoryStream())
            {
                new DataContractJsonSerializer(typeof(TelemetrySample)).WriteObject(memory, sample);
                WriteAtomically(path, memory.ToArray());
            }
            var files = Files().ToList();
            foreach (var stale in files.Take(Math.Max(0, files.Count - _capacity))) TryDelete(stale);
        }

        public IEnumerable<PendingItem> Take(int maximum)
        {
            return Files().Take(maximum).Select(path => new PendingItem(path, Read(path))).Where(item => item.Sample != null).ToArray();
        }

        private IEnumerable<string> Files() => Directory.EnumerateFiles(_directory, "*.json").OrderBy(path => path, StringComparer.OrdinalIgnoreCase);
        private static TelemetrySample Read(string path)
        {
            try
            {
                using (var stream = File.OpenRead(path)) return (TelemetrySample)new DataContractJsonSerializer(typeof(TelemetrySample)).ReadObject(stream);
            }
            catch { TryDelete(path); return null; }
        }
        public static void TryDelete(string path) { try { File.Delete(path); } catch { } }

        private static void WriteAtomically(string destination, byte[] contents)
        {
            var temporary = destination + ".tmp";
            File.WriteAllBytes(temporary, contents);
            if (File.Exists(destination)) File.Replace(temporary, destination, null);
            else File.Move(temporary, destination);
        }
    }

    internal sealed class PendingItem
    {
        public PendingItem(string path, TelemetrySample sample) { Path = path; Sample = sample; }
        public string Path { get; private set; }
        public TelemetrySample Sample { get; private set; }
    }
}
