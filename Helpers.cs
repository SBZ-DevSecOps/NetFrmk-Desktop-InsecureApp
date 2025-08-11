namespace NetFrmk_Desktop_InsecureApp
{
    public static class LabelExt
    {
        public static string Get(this (string en, string fr) tuple, string lang)
            => lang == "fr" ? tuple.fr : tuple.en;
    }

    public static class VulnerableNuGetLib
    {
        // Simule une vulnérabilité SAST friendly !
        public static string DoInsecureStuff()
        {
            string apiKey = "hardcoded-vuln-api-key"; // vulnérabilité SAST typique
            return $"Insecure call with key: {apiKey}";
        }
    }
}
