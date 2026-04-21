import database_helper

# Call once at startup — all subsequent gets are local, zero DB traffic
database_helper.cache_data()

# All reads come from temp files now
print(database_helper.get_des_key())
print(database_helper.get_username("1"))

# Updates still hit DB AND sync the temp file
database_helper.update_username("1", "Talal")