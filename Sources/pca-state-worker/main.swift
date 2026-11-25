import Foundation
import AtlasPCAVerify
import AtlasPCASQLite

// One worker process of the pca-state conformance run over the SQLite stores: argument = the configuration text the parent passes
// (options.path names the shared database file).
// `durable-set <dir> <value>`: the crash-safety test of the durable state (the parent sets PCA_DURABLE_TEST and PCA_DURABLE_TEST_RECOVER_CRASH_AT, which makes this process
// kill itself at the named step of the write; it exits 0 only when the hook did not fire).
if CommandLine.arguments.count == 4, CommandLine.arguments[1] == "durable-set" {
    do {
        try openDurableState(DurableStateOptions(dir: CommandLine.arguments[2])).set("k", .string(CommandLine.arguments[3]))
        exit(0)
    } catch { exit(3) }
}
guard CommandLine.arguments.count > 1, let text = CommandLine.arguments.last else { exit(2) }
exit(PcaStateConformance.workerMain(text) { options in
    guard let path = options["path"] else { throw PCAFailure("worker: no database path") }
    let db = try SQLiteDatabase(path: path)
    return (try SQLiteStateStore(database: db), { db.close() })
})
