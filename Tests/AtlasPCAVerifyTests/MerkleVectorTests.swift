import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The RFC 6962 Merkle tree pinned against independently computed roots and inclusion proofs (Python hashlib): every tree size
/// 1...17 and the power-of-two boundaries, leaves {"i": k}, plus every way a proof can be wrong.
final class MerkleVectorTests: XCTestCase {
    private static let roots: [(Int, String)] = [
        (1, "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"),
        (2, "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U"),
        (3, "AKcKsZUbOSDpO7cxOBdBlx0JYMGuQc5ky21fozC__MY"),
        (4, "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"),
        (5, "OWzC8-pXpLvOMYsH2CT91q0pLUsT6Q9WrpQRsWTbETY"),
        (6, "px-xtSlHTbvcUL3tvBJmgAHlDRhxx2X23RNRBzAeuOg"),
        (7, "6cbV7VEnsBt5QB48I9xhI2QC-_96slqu34GAhl2pSs0"),
        (8, "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0"),
        (9, "2Nk2HmnwwT96CA1INp_iksK0TqCZC0BoTACqL1Al2l8"),
        (10, "exHVjtuIYf4YCCnsdTGFo2B8Js0P32AsGdetTPzRnMA"),
        (11, "lJzkMUq_jSiY_8L_Fyy7Gyel4ku0kpw78D81CAZflGY"),
        (12, "Nvev-th-ui47dWJx6r_jB7cjeLAZXpWGQ_kemNKtWEo"),
        (13, "Ko6WjypuZWoDQqA09vAw_y0Lf3ia2fbr_rOxoFsV4u8"),
        (14, "W-F8pzr_jgiwZRo4qjarKv3WtiuL2uscO7aLrgkFm60"),
        (15, "8E5Toj0VoRmCkJinzAKf71252EBVCucylZeKNLh3Dxs"),
        (16, "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc"),
        (17, "qOZ6wpdmrvht77x7bQf4JEZDO11sVg_bWGQkCRGnkck"),
        (31, "Fjc6RhUdD5nXPyGmKanePZkOcK-sXr_gPQ7irAHVIhw"),
        (32, "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY"),
        (33, "NAV6GUZxXgwvuTsOn53-qvrCv4BbsVKyIxpA9CR4rrY"),
        (64, "vvTK1Xzo1tBOuTQM1-5B_HpLgAuN5W3GiLI9FEbNOjY"),
        (65, "xz31OxkLAi5WIxiOsJHFLalrxoRsIBvEcTZJjMSOr4o")
    ]
    // (size, index, root, path [(side, hash)] leaf -> root)
    private static let proofs: [(Int, Int, String, [(String, String)])] = [
        (1, 0, "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE", []),
        (2, 0, "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc")]),
        (2, 1, "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE")]),
        (3, 0, "AKcKsZUbOSDpO7cxOBdBlx0JYMGuQc5ky21fozC__MY", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "3t8ellaME6WCe7y4TZIK2yHZibXaT2Hea9Bg5SeS2pE")]),
        (3, 1, "AKcKsZUbOSDpO7cxOBdBlx0JYMGuQc5ky21fozC__MY", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "3t8ellaME6WCe7y4TZIK2yHZibXaT2Hea9Bg5SeS2pE")]),
        (3, 2, "AKcKsZUbOSDpO7cxOBdBlx0JYMGuQc5ky21fozC__MY", [("L", "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U")]),
        (4, 0, "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE")]),
        (4, 1, "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE")]),
        (4, 2, "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU", [("R", "gR-MJClAf_75fl1Ogf-IsSZJHIFQFu7-yHl8q59j0SU"), ("L", "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U")]),
        (4, 3, "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU", [("L", "3t8ellaME6WCe7y4TZIK2yHZibXaT2Hea9Bg5SeS2pE"), ("L", "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U")]),
        (5, 0, "OWzC8-pXpLvOMYsH2CT91q0pLUsT6Q9WrpQRsWTbETY", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE")]),
        (5, 1, "OWzC8-pXpLvOMYsH2CT91q0pLUsT6Q9WrpQRsWTbETY", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE")]),
        (5, 2, "OWzC8-pXpLvOMYsH2CT91q0pLUsT6Q9WrpQRsWTbETY", [("R", "gR-MJClAf_75fl1Ogf-IsSZJHIFQFu7-yHl8q59j0SU"), ("L", "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U"), ("R", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE")]),
        (5, 4, "OWzC8-pXpLvOMYsH2CT91q0pLUsT6Q9WrpQRsWTbETY", [("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU")]),
        (6, 0, "px-xtSlHTbvcUL3tvBJmgAHlDRhxx2X23RNRBzAeuOg", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA")]),
        (6, 1, "px-xtSlHTbvcUL3tvBJmgAHlDRhxx2X23RNRBzAeuOg", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA")]),
        (6, 3, "px-xtSlHTbvcUL3tvBJmgAHlDRhxx2X23RNRBzAeuOg", [("L", "3t8ellaME6WCe7y4TZIK2yHZibXaT2Hea9Bg5SeS2pE"), ("L", "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U"), ("R", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA")]),
        (6, 5, "px-xtSlHTbvcUL3tvBJmgAHlDRhxx2X23RNRBzAeuOg", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU")]),
        (7, 0, "6cbV7VEnsBt5QB48I9xhI2QC-_96slqu34GAhl2pSs0", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "5IixK2We8g2SjTfhRkvvtuv1yrandXJANT_RDZ7TLJo")]),
        (7, 1, "6cbV7VEnsBt5QB48I9xhI2QC-_96slqu34GAhl2pSs0", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "5IixK2We8g2SjTfhRkvvtuv1yrandXJANT_RDZ7TLJo")]),
        (7, 3, "6cbV7VEnsBt5QB48I9xhI2QC-_96slqu34GAhl2pSs0", [("L", "3t8ellaME6WCe7y4TZIK2yHZibXaT2Hea9Bg5SeS2pE"), ("L", "jXl7tY1h9ngEf9-So5ARexbYcYuVcwOpIxo2z24MX3U"), ("R", "5IixK2We8g2SjTfhRkvvtuv1yrandXJANT_RDZ7TLJo")]),
        (7, 5, "6cbV7VEnsBt5QB48I9xhI2QC-_96slqu34GAhl2pSs0", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "Ig7PSzxT7zMuOnplhEQ7JNFb0NBYq-Xm3nUg37v4ihg"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU")]),
        (7, 6, "6cbV7VEnsBt5QB48I9xhI2QC-_96slqu34GAhl2pSs0", [("L", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU")]),
        (8, 0, "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw")]),
        (8, 1, "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw")]),
        (8, 4, "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0", [("R", "zWPy0SLaWx8aqkQ8Thh-Iy6cZFHUz63vxuK1X4fjeQs"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU")]),
        (8, 5, "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU")]),
        (8, 7, "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0", [("L", "Ig7PSzxT7zMuOnplhEQ7JNFb0NBYq-Xm3nUg37v4ihg"), ("L", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU")]),
        (9, 0, "2Nk2HmnwwT96CA1INp_iksK0TqCZC0BoTACqL1Al2l8", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "D72mjVRCspZeVuAFCzecN9dK1CQ8htOiEeq6DiTFwoM")]),
        (9, 1, "2Nk2HmnwwT96CA1INp_iksK0TqCZC0BoTACqL1Al2l8", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "D72mjVRCspZeVuAFCzecN9dK1CQ8htOiEeq6DiTFwoM")]),
        (9, 4, "2Nk2HmnwwT96CA1INp_iksK0TqCZC0BoTACqL1Al2l8", [("R", "zWPy0SLaWx8aqkQ8Thh-Iy6cZFHUz63vxuK1X4fjeQs"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "D72mjVRCspZeVuAFCzecN9dK1CQ8htOiEeq6DiTFwoM")]),
        (9, 5, "2Nk2HmnwwT96CA1INp_iksK0TqCZC0BoTACqL1Al2l8", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "D72mjVRCspZeVuAFCzecN9dK1CQ8htOiEeq6DiTFwoM")]),
        (9, 8, "2Nk2HmnwwT96CA1INp_iksK0TqCZC0BoTACqL1Al2l8", [("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (10, 0, "exHVjtuIYf4YCCnsdTGFo2B8Js0P32AsGdetTPzRnMA", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "bufyoUEhjnbb842V7wia-olm2AR7mZKxplrjXWqIkPU")]),
        (10, 1, "exHVjtuIYf4YCCnsdTGFo2B8Js0P32AsGdetTPzRnMA", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "bufyoUEhjnbb842V7wia-olm2AR7mZKxplrjXWqIkPU")]),
        (10, 5, "exHVjtuIYf4YCCnsdTGFo2B8Js0P32AsGdetTPzRnMA", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "bufyoUEhjnbb842V7wia-olm2AR7mZKxplrjXWqIkPU")]),
        (10, 9, "exHVjtuIYf4YCCnsdTGFo2B8Js0P32AsGdetTPzRnMA", [("L", "D72mjVRCspZeVuAFCzecN9dK1CQ8htOiEeq6DiTFwoM"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (11, 0, "lJzkMUq_jSiY_8L_Fyy7Gyel4ku0kpw78D81CAZflGY", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "IwiSUb2keSzwwVsmk08Ep8rgmwwj3f25c7bVL5qO5_w")]),
        (11, 1, "lJzkMUq_jSiY_8L_Fyy7Gyel4ku0kpw78D81CAZflGY", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "IwiSUb2keSzwwVsmk08Ep8rgmwwj3f25c7bVL5qO5_w")]),
        (11, 5, "lJzkMUq_jSiY_8L_Fyy7Gyel4ku0kpw78D81CAZflGY", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "IwiSUb2keSzwwVsmk08Ep8rgmwwj3f25c7bVL5qO5_w")]),
        (11, 10, "lJzkMUq_jSiY_8L_Fyy7Gyel4ku0kpw78D81CAZflGY", [("L", "bufyoUEhjnbb842V7wia-olm2AR7mZKxplrjXWqIkPU"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (12, 0, "Nvev-th-ui47dWJx6r_jB7cjeLAZXpWGQ_kemNKtWEo", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY")]),
        (12, 1, "Nvev-th-ui47dWJx6r_jB7cjeLAZXpWGQ_kemNKtWEo", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY")]),
        (12, 5, "Nvev-th-ui47dWJx6r_jB7cjeLAZXpWGQ_kemNKtWEo", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY")]),
        (12, 6, "Nvev-th-ui47dWJx6r_jB7cjeLAZXpWGQ_kemNKtWEo", [("R", "umqHFKuLgd7yYJofk03eIrqPLxITU6eVguUD19C7eXA"), ("L", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY")]),
        (12, 11, "Nvev-th-ui47dWJx6r_jB7cjeLAZXpWGQ_kemNKtWEo", [("L", "BAUHV7J7FInHpFFyvz7iVDgDp-LHYWwL5FNFfUgln4Y"), ("L", "bufyoUEhjnbb842V7wia-olm2AR7mZKxplrjXWqIkPU"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (13, 0, "Ko6WjypuZWoDQqA09vAw_y0Lf3ia2fbr_rOxoFsV4u8", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "XprDXikdM4rg9swlxLjU2NWRUx2aw1OiHhvJLLrKVKY")]),
        (13, 1, "Ko6WjypuZWoDQqA09vAw_y0Lf3ia2fbr_rOxoFsV4u8", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "XprDXikdM4rg9swlxLjU2NWRUx2aw1OiHhvJLLrKVKY")]),
        (13, 5, "Ko6WjypuZWoDQqA09vAw_y0Lf3ia2fbr_rOxoFsV4u8", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "XprDXikdM4rg9swlxLjU2NWRUx2aw1OiHhvJLLrKVKY")]),
        (13, 6, "Ko6WjypuZWoDQqA09vAw_y0Lf3ia2fbr_rOxoFsV4u8", [("R", "umqHFKuLgd7yYJofk03eIrqPLxITU6eVguUD19C7eXA"), ("L", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "XprDXikdM4rg9swlxLjU2NWRUx2aw1OiHhvJLLrKVKY")]),
        (13, 12, "Ko6WjypuZWoDQqA09vAw_y0Lf3ia2fbr_rOxoFsV4u8", [("L", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (14, 0, "W-F8pzr_jgiwZRo4qjarKv3WtiuL2uscO7aLrgkFm60", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "VYVukqrhFz8KiClFXOYHz4641wtLpOAaEIKAwHpBP_4")]),
        (14, 1, "W-F8pzr_jgiwZRo4qjarKv3WtiuL2uscO7aLrgkFm60", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "VYVukqrhFz8KiClFXOYHz4641wtLpOAaEIKAwHpBP_4")]),
        (14, 5, "W-F8pzr_jgiwZRo4qjarKv3WtiuL2uscO7aLrgkFm60", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "VYVukqrhFz8KiClFXOYHz4641wtLpOAaEIKAwHpBP_4")]),
        (14, 7, "W-F8pzr_jgiwZRo4qjarKv3WtiuL2uscO7aLrgkFm60", [("L", "Ig7PSzxT7zMuOnplhEQ7JNFb0NBYq-Xm3nUg37v4ihg"), ("L", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "VYVukqrhFz8KiClFXOYHz4641wtLpOAaEIKAwHpBP_4")]),
        (14, 13, "W-F8pzr_jgiwZRo4qjarKv3WtiuL2uscO7aLrgkFm60", [("L", "FyAX4NV2X_6oIWpkZijQRXVIUrGwKaOxR0jRpPVVFYM"), ("L", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (15, 0, "8E5Toj0VoRmCkJinzAKf71252EBVCucylZeKNLh3Dxs", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "KTHA3dAOMiY885HWe8sA8fTRQiI-SPJuAYFPUaupggg")]),
        (15, 1, "8E5Toj0VoRmCkJinzAKf71252EBVCucylZeKNLh3Dxs", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "KTHA3dAOMiY885HWe8sA8fTRQiI-SPJuAYFPUaupggg")]),
        (15, 5, "8E5Toj0VoRmCkJinzAKf71252EBVCucylZeKNLh3Dxs", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "KTHA3dAOMiY885HWe8sA8fTRQiI-SPJuAYFPUaupggg")]),
        (15, 7, "8E5Toj0VoRmCkJinzAKf71252EBVCucylZeKNLh3Dxs", [("L", "Ig7PSzxT7zMuOnplhEQ7JNFb0NBYq-Xm3nUg37v4ihg"), ("L", "el9IKrsNpCo-KtBVIwfm_pg0I71PaE6ReG0gDWP6PtA"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "KTHA3dAOMiY885HWe8sA8fTRQiI-SPJuAYFPUaupggg")]),
        (15, 14, "8E5Toj0VoRmCkJinzAKf71252EBVCucylZeKNLh3Dxs", [("L", "giRHcvUlt5dFvcz5-BXsEG6sQ2ep5mw88VbC5aT3u4k"), ("L", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (16, 0, "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys")]),
        (16, 1, "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys")]),
        (16, 5, "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys")]),
        (16, 8, "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc", [("R", "1B3HrmU1fVxo3uVGkM-YYvneB247t4AehNdSluBxIKA"), ("R", "At4gXPaN1DUUeAk5Pha8iRc7Syh0BSF6RB9FH0CIBJ0"), ("R", "laiL0ClEc49W7bM-UFrMp9FnZlvivs7pdUZN15DAxzE"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (16, 15, "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc", [("L", "exFkrslq4WrXIzh0Z4VGBRfc9FV6V8-Jl7ALhzDxz4s"), ("L", "giRHcvUlt5dFvcz5-BXsEG6sQ2ep5mw88VbC5aT3u4k"), ("L", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0")]),
        (17, 0, "qOZ6wpdmrvht77x7bQf4JEZDO11sVg_bWGQkCRGnkck", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "gg7t_X5tEbCdLdJRt4OrAy5aQjgBraXLwvxqxTFLRog")]),
        (17, 1, "qOZ6wpdmrvht77x7bQf4JEZDO11sVg_bWGQkCRGnkck", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "gg7t_X5tEbCdLdJRt4OrAy5aQjgBraXLwvxqxTFLRog")]),
        (17, 5, "qOZ6wpdmrvht77x7bQf4JEZDO11sVg_bWGQkCRGnkck", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "gg7t_X5tEbCdLdJRt4OrAy5aQjgBraXLwvxqxTFLRog")]),
        (17, 8, "qOZ6wpdmrvht77x7bQf4JEZDO11sVg_bWGQkCRGnkck", [("R", "1B3HrmU1fVxo3uVGkM-YYvneB247t4AehNdSluBxIKA"), ("R", "At4gXPaN1DUUeAk5Pha8iRc7Syh0BSF6RB9FH0CIBJ0"), ("R", "laiL0ClEc49W7bM-UFrMp9FnZlvivs7pdUZN15DAxzE"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0"), ("R", "gg7t_X5tEbCdLdJRt4OrAy5aQjgBraXLwvxqxTFLRog")]),
        (17, 16, "qOZ6wpdmrvht77x7bQf4JEZDO11sVg_bWGQkCRGnkck", [("L", "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc")]),
        (31, 0, "Fjc6RhUdD5nXPyGmKanePZkOcK-sXr_gPQ7irAHVIhw", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "mLm4bM9nhRpexaOp9zhnyVaId3xkHeAeRlk3YfOGiH0")]),
        (31, 1, "Fjc6RhUdD5nXPyGmKanePZkOcK-sXr_gPQ7irAHVIhw", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "mLm4bM9nhRpexaOp9zhnyVaId3xkHeAeRlk3YfOGiH0")]),
        (31, 5, "Fjc6RhUdD5nXPyGmKanePZkOcK-sXr_gPQ7irAHVIhw", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "mLm4bM9nhRpexaOp9zhnyVaId3xkHeAeRlk3YfOGiH0")]),
        (31, 15, "Fjc6RhUdD5nXPyGmKanePZkOcK-sXr_gPQ7irAHVIhw", [("L", "exFkrslq4WrXIzh0Z4VGBRfc9FV6V8-Jl7ALhzDxz4s"), ("L", "giRHcvUlt5dFvcz5-BXsEG6sQ2ep5mw88VbC5aT3u4k"), ("L", "T4uCzLXs42I3yVMWvwNLyaJULhaE4mBu0ClOTOxzvWY"), ("L", "xSuQ_7kn4fp3O0JdJQx2lnp5fvADJH8mVd9wnTfxzk0"), ("R", "mLm4bM9nhRpexaOp9zhnyVaId3xkHeAeRlk3YfOGiH0")]),
        (31, 30, "Fjc6RhUdD5nXPyGmKanePZkOcK-sXr_gPQ7irAHVIhw", [("L", "CHe3Xqenzw6bl02p3wRDemr2m4uiU2kV53gafBys29Y"), ("L", "3ErNj1HndM5jpmuLWDON3tC-QnQGihcjS3LPbELNFrc"), ("L", "h9jqH5xT1tx5nNZPZWviSGYI4WCxqcXfAntpLUc2gck"), ("L", "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc")]),
        (32, 0, "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0")]),
        (32, 1, "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0")]),
        (32, 5, "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0")]),
        (32, 16, "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY", [("R", "_f6tyDRps6sezi2WqeLhbpPn-UKjj1s3if55pSdlR48"), ("R", "jVk9es_Z82MZeYjcTZJcxC8ke_2yu8cl4kwTmRv-Bqw"), ("R", "1E6F48Mjgls5BSq0SUkNwF-v3vXc0D5czqcLh17Rmgg"), ("R", "PMQ5tBMexrGpcmLL5M58ThwT0e48HzriVMbQZDmpVss"), ("L", "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc")]),
        (32, 31, "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY", [("L", "Jjni6fOFCDwb71HAczCfDRf_NvxhlTv4o0RAKXPMVrk"), ("L", "CHe3Xqenzw6bl02p3wRDemr2m4uiU2kV53gafBys29Y"), ("L", "3ErNj1HndM5jpmuLWDON3tC-QnQGihcjS3LPbELNFrc"), ("L", "h9jqH5xT1tx5nNZPZWviSGYI4WCxqcXfAntpLUc2gck"), ("L", "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc")]),
        (33, 0, "NAV6GUZxXgwvuTsOn53-qvrCv4BbsVKyIxpA9CR4rrY", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "7Y_wfiiV08y22WA30pmC_fr92tRLR9xE01i2Vwh1ddQ")]),
        (33, 1, "NAV6GUZxXgwvuTsOn53-qvrCv4BbsVKyIxpA9CR4rrY", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "7Y_wfiiV08y22WA30pmC_fr92tRLR9xE01i2Vwh1ddQ")]),
        (33, 5, "NAV6GUZxXgwvuTsOn53-qvrCv4BbsVKyIxpA9CR4rrY", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "7Y_wfiiV08y22WA30pmC_fr92tRLR9xE01i2Vwh1ddQ")]),
        (33, 16, "NAV6GUZxXgwvuTsOn53-qvrCv4BbsVKyIxpA9CR4rrY", [("R", "_f6tyDRps6sezi2WqeLhbpPn-UKjj1s3if55pSdlR48"), ("R", "jVk9es_Z82MZeYjcTZJcxC8ke_2yu8cl4kwTmRv-Bqw"), ("R", "1E6F48Mjgls5BSq0SUkNwF-v3vXc0D5czqcLh17Rmgg"), ("R", "PMQ5tBMexrGpcmLL5M58ThwT0e48HzriVMbQZDmpVss"), ("L", "CgrG-tsAhZS_2xWeUsi22gB0Mr_Fd03N__3vSJsEVXc"), ("R", "7Y_wfiiV08y22WA30pmC_fr92tRLR9xE01i2Vwh1ddQ")]),
        (33, 32, "NAV6GUZxXgwvuTsOn53-qvrCv4BbsVKyIxpA9CR4rrY", [("L", "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY")]),
        (64, 0, "vvTK1Xzo1tBOuTQM1-5B_HpLgAuN5W3GiLI9FEbNOjY", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "qmLZPIDwLqaZerlCjBpKYb7J5y1hVxVMIj-zHNtxHMo")]),
        (64, 1, "vvTK1Xzo1tBOuTQM1-5B_HpLgAuN5W3GiLI9FEbNOjY", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "qmLZPIDwLqaZerlCjBpKYb7J5y1hVxVMIj-zHNtxHMo")]),
        (64, 5, "vvTK1Xzo1tBOuTQM1-5B_HpLgAuN5W3GiLI9FEbNOjY", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "qmLZPIDwLqaZerlCjBpKYb7J5y1hVxVMIj-zHNtxHMo")]),
        (64, 32, "vvTK1Xzo1tBOuTQM1-5B_HpLgAuN5W3GiLI9FEbNOjY", [("R", "1i5djwuJphPwoUUUnjWAbNAWTNQv6iBJz0Cuj4hS7s8"), ("R", "8BH4hfCYKFTAgsHZq-JqtuKqrFKepOKlP0PpasSFBfI"), ("R", "y65wReqU82-tDUcbjG6p5z8uZ6crUjsOal6eg2-ppJc"), ("R", "EZwkdIwpzqoGS1joHwHCPEw2NWRmm8JXDIXvdJUbIo8"), ("R", "Jl18fbkLGaru4oSClGQyjopzoMi3Y00mdlsGsZoR9OM"), ("L", "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY")]),
        (64, 63, "vvTK1Xzo1tBOuTQM1-5B_HpLgAuN5W3GiLI9FEbNOjY", [("L", "KLfFp5tof0w7aqgVIYRojqcun-HAbnOvOBHXKO0uEaI"), ("L", "1TtJP54VXC1GQUAgw3FMl9-J-Xvq52XhGXLPQsUbaxs"), ("L", "R5G1JPodk5pQadvOpegHueMavQwE-0LaXQAMoT0_UCI"), ("L", "Inx7hCZpI3FmE0vcaHbCMb80I7yvVCBzpxRTkMwt5yQ"), ("L", "o2X9lQV641ElLyWOoXXrxl0KmCpjvpA--6NKRJkWI_U"), ("L", "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY")]),
        (65, 0, "xz31OxkLAi5WIxiOsJHFLalrxoRsIBvEcTZJjMSOr4o", [("R", "wtZUma2JpeznH5J8yDlciAS_v2Gy2sR1GHqhaW-jYEc"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "qmLZPIDwLqaZerlCjBpKYb7J5y1hVxVMIj-zHNtxHMo"), ("R", "Rp23NHZijL3m2nUPvoHcHiQmzMx_SPFwmPqwxM7qga0")]),
        (65, 1, "xz31OxkLAi5WIxiOsJHFLalrxoRsIBvEcTZJjMSOr4o", [("L", "2Cnt0HE6G7BePNBhaSSkxb3iHjblNxSaICOe2vqIJfE"), ("R", "2aIGql3zwzmnXJtQU9Wn1ABOFSWusGvlTDSmi93R3nE"), ("R", "XR2VSzeuNFkiJ6B1PnqqwjRedODLRAPyE57iDhocDsw"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "qmLZPIDwLqaZerlCjBpKYb7J5y1hVxVMIj-zHNtxHMo"), ("R", "Rp23NHZijL3m2nUPvoHcHiQmzMx_SPFwmPqwxM7qga0")]),
        (65, 5, "xz31OxkLAi5WIxiOsJHFLalrxoRsIBvEcTZJjMSOr4o", [("L", "VAZmcWJr-jVQiIzLFHPW-pMPjB8FUW32AfrPCRRf-CE"), ("R", "kGyHEw23k98-0mdGrt0N0LuM9_kamP5vP8o7dGS9HzM"), ("L", "hkH548xF2RdwxU4-XUd9PO7ztp8GA8EgsuKSk2RIBtU"), ("R", "rbEdQHmdhwbI7KNWsP8MKdMhRM-0EczcJ5QXFm7aXys"), ("R", "AcgzDjJVrFwMrCQ97uWXgPEGEeBxC8n1VSNljf_xPC0"), ("R", "qmLZPIDwLqaZerlCjBpKYb7J5y1hVxVMIj-zHNtxHMo"), ("R", "Rp23NHZijL3m2nUPvoHcHiQmzMx_SPFwmPqwxM7qga0")]),
        (65, 32, "xz31OxkLAi5WIxiOsJHFLalrxoRsIBvEcTZJjMSOr4o", [("R", "1i5djwuJphPwoUUUnjWAbNAWTNQv6iBJz0Cuj4hS7s8"), ("R", "8BH4hfCYKFTAgsHZq-JqtuKqrFKepOKlP0PpasSFBfI"), ("R", "y65wReqU82-tDUcbjG6p5z8uZ6crUjsOal6eg2-ppJc"), ("R", "EZwkdIwpzqoGS1joHwHCPEw2NWRmm8JXDIXvdJUbIo8"), ("R", "Jl18fbkLGaru4oSClGQyjopzoMi3Y00mdlsGsZoR9OM"), ("L", "r-ALfmlPLpmQUpJEdc0xR4Yuon1wcuWjNCT8sVJebKY"), ("R", "Rp23NHZijL3m2nUPvoHcHiQmzMx_SPFwmPqwxM7qga0")]),
        (65, 64, "xz31OxkLAi5WIxiOsJHFLalrxoRsIBvEcTZJjMSOr4o", [("L", "vvTK1Xzo1tBOuTQM1-5B_HpLgAuN5W3GiLI9FEbNOjY")])
    ]

    private func leaf(_ k: Int) -> JSONValue { .object([JKey("i"): .int(Int64(k))]) }
    private func proof(_ size: Int, _ index: Int, _ path: [(String, String)]) -> JObject {
        ["size": .int(Int64(size)), "index": .int(Int64(index)),
         "path": .array(path.map { .object(["side": .string($0.0), "hash": .string($0.1)]) })]
    }

    func testRootsMatch() {
        for (n, root) in Self.roots { XCTAssertEqual(Merkle.merkleRoot((0..<n).map(leaf)), root, "root of \(n) leaves") }
        XCTAssertNil(Merkle.merkleRoot([]))
    }

    func testSplitIsTheLargestPowerOfTwoBelowN() {
        let want: [(UInt64, UInt64)] = [(2, 1), (3, 2), (4, 2), (5, 4), (8, 4), (9, 8), (16, 8), (17, 16), (31, 16), (32, 16), (33, 32), (1000, 512), (1025, 1024)]
        for (n, k) in want { XCTAssertEqual(Merkle.split(n), k, "split(\(n))") }
        XCTAssertEqual(Merkle.split(1), 1)
    }

    func testInclusionProofsVerifyAndRejectEveryTamper() {
        XCTAssertGreaterThan(Self.proofs.count, 60)
        for (n, idx, root, path) in Self.proofs {
            let p = proof(n, idx, path)
            XCTAssertTrue(Merkle.verifyInclusion(root, p, leaf(idx)), "proof \(idx)/\(n)")
            XCTAssertFalse(Merkle.verifyInclusion(root, p, leaf(idx + 1)), "wrong leaf \(idx)/\(n)")
            if !path.isEmpty { XCTAssertFalse(Merkle.verifyInclusion(root, proof(n, idx, Array(path.dropLast())), leaf(idx)), "short path \(idx)/\(n)") }
            XCTAssertFalse(Merkle.verifyInclusion(root, proof(n, idx, path + [("L", path.first?.1 ?? root)]), leaf(idx)), "long path \(idx)/\(n)")
            if n > 1 {
                XCTAssertFalse(Merkle.verifyInclusion(root, proof(n, (idx + 1) % n, path), leaf(idx)), "wrong index \(idx)/\(n)")
                var flipped = path
                flipped[0].0 = flipped[0].0 == "L" ? "R" : "L"
                XCTAssertFalse(Merkle.verifyInclusion(root, proof(n, idx, flipped), leaf(idx)), "flipped side \(idx)/\(n)")
            }
            if Merkle.pathShape(UInt64(idx), UInt64(n + 1)) != Merkle.pathShape(UInt64(idx), UInt64(n)) { XCTAssertFalse(Merkle.verifyInclusion(root, proof(n + 1, idx, path), leaf(idx)), "wrong size \(idx)/\(n)") }
            XCTAssertFalse(Merkle.verifyInclusion(root, proof(n, -1, path), leaf(idx)), "index -1")
            XCTAssertFalse(Merkle.verifyInclusion(root, proof(n, n, path), leaf(idx)), "index == size")
            XCTAssertFalse(Merkle.verifyInclusion(root, proof(0, 0, path), leaf(idx)), "size 0")
            XCTAssertFalse(Merkle.verifyInclusion(root, proof(-1, 0, path), leaf(idx)), "size -1")
            XCTAssertFalse(Merkle.verifyInclusion(Base64URLStrict.encode(Canonical.sha256([9])), p, leaf(idx)), "other root")
        }
        XCTAssertFalse(Merkle.verifyInclusion("x", nil, leaf(0)))
    }

    func testSingleLeafTree() {
        let root = Merkle.merkleRoot([leaf(0)])!
        XCTAssertTrue(Merkle.verifyInclusion(root, proof(1, 0, []), leaf(0)))
        XCTAssertFalse(Merkle.verifyInclusion(root, proof(1, 0, []), leaf(1)))
        XCTAssertFalse(Merkle.verifyInclusion(root, proof(1, 1, []), leaf(0)))
        XCTAssertFalse(Merkle.verifyInclusion(root, proof(1, -1, []), leaf(0)))
        XCTAssertFalse(Merkle.verifyInclusion(root, proof(0, 0, []), leaf(0)))
    }

    func testPathShape() {
        XCTAssertEqual(Merkle.pathShape(0, 1), [])
        XCTAssertEqual(String(decoding: Merkle.pathShape(0, 2), as: UTF8.self), "R")
        XCTAssertEqual(String(decoding: Merkle.pathShape(1, 2), as: UTF8.self), "L")
        XCTAssertEqual(String(decoding: Merkle.pathShape(0, 3), as: UTF8.self), "RR")
        XCTAssertEqual(String(decoding: Merkle.pathShape(2, 3), as: UTF8.self), "L")
        XCTAssertEqual(String(decoding: Merkle.pathShape(4, 5), as: UTF8.self), "L")
        XCTAssertEqual(String(decoding: Merkle.pathShape(3, 7), as: UTF8.self), "LLR")
    }

    func testBuildOfASingleHashIsThatHash() {
        let h = Canonical.sha256([1, 2, 3])
        XCTAssertEqual(Merkle.build([h]), h)
        XCTAssertEqual(Merkle.build([h, h]), Merkle.nodeHash(h, h))
    }
}
