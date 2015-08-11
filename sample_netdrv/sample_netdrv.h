
struct sample_stats {
        u64                     packets;
        u64                     bytes;
};

struct sample_priv {
	/* wd nmap must be the first member in the structure */
	struct wd_nmap_info wd_nmap;
	int val;
	struct sample_stats stats;
};

