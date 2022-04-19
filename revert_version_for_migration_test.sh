VERSION=$(grep 'static MIGRATION_TEST_VERSION' ./src/handlers/migrate_handler.rs | sed 's/static MIGRATION_TEST_VERSION: u32 = \(.*\);/\1/')

perl -pi -e "s/static MIGRATION_TEST_VERSION: u32 = .*;/static MIGRATION_TEST_VERSION: u32 = VERSION;/" src/handlers/migrate_handler.rs
perl -pi -e "s/pub static VERSION: u32 = 0;/pub static VERSION: u32 = ${VERSION};/" src/version.rs
