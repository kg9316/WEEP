using Weep.Client;

namespace Weep.Examples;

/// <summary>
/// Eksempel: browse og last ned filer fra en weep-server.
///
/// Forutsetter at serveren kjører på port 9000 (Python eller C#):
///   python -m weep.server --port 9000
///   -- eller --
///   dotnet run --project csharp/weep.TestRunner -- --server-only
///
/// Kjør:
///   var example = new BrowseAndDownload();
///   await example.RunAsync();
/// </summary>
public sealed class BrowseAndDownload
{
    private const string ServerUrl = "ws://localhost:9000";

    public async Task RunAsync(CancellationToken ct = default)
    {
        Console.WriteLine($"Kobler til {ServerUrl} ...");

        await using var client = new WeepClient();
        var auth = new AuthClient(client);

        await client.ConnectAsync(new Uri(ServerUrl), ct);

        // --- Autentisering ---
        var greeting = await auth.WaitForGreetingAsync(ct);
        Console.WriteLine($"Server støtter: {string.Join(", ", greeting.Profiles)}");
        Console.WriteLine($"Auth:           {string.Join(", ", greeting.AuthMechanisms)}");

        var user = await auth.LoginWithChallengeAsync("admin", "admin", ct);
        Console.WriteLine($"Logget inn som '{user.Username}' roller=[{string.Join(", ", user.Roles)}]\n");

        // --- Åpne fil-kanal ---
        await using var ft = new FileTransferClient(client);
        await ft.OpenAsync(ct);

        // --- Brows filtre rekursivt ---
        Console.WriteLine("=== Filtre på server ===");
        await PrintTreeAsync(ft, "/", 0, ct);
        Console.WriteLine();

        // --- Finn første fil i roten ---
        var root  = await ft.ListAsync("/", ct);
        var files = root.Files.ToList();

        if (files.Count == 0)
        {
            Console.WriteLine("Ingen filer på serveren ennå. Laster opp testfil ...");

            var tmpFile = Path.GetTempFileName();
            await File.WriteAllTextAsync(tmpFile,
                string.Concat(Enumerable.Repeat("Hello from weep!\n", 100)), ct);

            await ft.UploadAsync(tmpFile, "/weep_test.txt",
                progress: new Progress<double>(p =>
                    Console.Write($"\r  Upload: {p * 100:F0}%  ")), ct: ct);
            Console.WriteLine("\nOpplastet /weep_test.txt");

            root  = await ft.ListAsync("/", ct);
            files = root.Files.ToList();
        }

        if (files.Count > 0)
        {
            var target = files[0];

            // --- Stat: les metadata ---
            var info = await ft.StatAsync(target.Path, ct);
            Console.WriteLine($"=== Stat for {info.Path} ===");
            Console.WriteLine($"  Navn:      {info.Name}");
            Console.WriteLine($"  Størrelse: {info.Size} bytes");
            Console.WriteLine($"  MIME:      {info.Mime}");
            Console.WriteLine($"  Endret:    {info.Modified}");
            Console.WriteLine();

            // --- Last ned ved hjelp av path fra stat ---
            var localDest = Path.Combine(Path.GetTempPath(), $"downloaded_{info.Name}");
            Console.WriteLine($"Laster ned {info.Path} → {localDest} ...");

            await ft.DownloadAsync(info.Path, localDest,
                progress: new Progress<double>(p =>
                {
                    var filled = (int)(p * 30);
                    var bar    = new string('█', filled) + new string('░', 30 - filled);
                    Console.Write($"\r  [{bar}] {p * 100:F1}%");
                }), ct: ct);

            var downloaded = new FileInfo(localDest).Length;
            Console.WriteLine($"\nFerdig!  Lastet ned {downloaded} bytes → {localDest}");
        }
    }

    // ------------------------------------------------------------------
    // Hjelpemetode: rekursiv utskrift av filtre
    // ------------------------------------------------------------------

    private static async Task PrintTreeAsync(FileTransferClient ft,
                                              string path, int indent,
                                              CancellationToken ct)
    {
        var listing = await ft.ListAsync(path, ct);
        var prefix  = new string(' ', indent * 2);

        foreach (var entry in listing.Entries)
        {
            if (entry.IsDir)
            {
                Console.WriteLine($"{prefix}[DIR]  {entry.Name}/");
                await PrintTreeAsync(ft, entry.Path, indent + 1, ct);
            }
            else
            {
                Console.WriteLine($"{prefix}[FILE] {entry.Name,-30} " +
                                  $"{entry.Size,8} bytes  {entry.Mime}");
            }
        }
    }
}
