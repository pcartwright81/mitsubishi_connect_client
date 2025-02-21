"""File for tests."""

test_vehicles_response = """
        {
            "vehicles": [
                {
                    "vin": "vin",
                    "dateOfSale": "2024-12-29",
                    "primaryUser": true,
                    "make": "make",
                    "model": "model",
                    "year": "2024",
                    "exteriorColorCode": "exteriorColorCode",
                    "exteriorColor": "exteriorColor",
                    "simState": "simState",
                    "modelDescription": "modelDescription",
                    "country": "country",
                    "region": "region",
                    "alphaThreeCountryCode": "alphaThreeCountryCode",
                    "countryName": "countryName",
                    "isFleet": false
                }
            ]
        }
        """

test_vehicle_state_response = """
            {
                "vin": "1234567890ABCDEFG",
                "ts": "2024-03-14T12:34:56.789Z",
                "state": {
                    "extLocMap": {
                        "lon": 123.456,
                        "lat": 456.789,
                        "ts": "1678886400000"
                    },
                    "cst": "1",
                    "tuState": "1",
                    "ods": "0",
                    "ignitionState": "0",
                    "odo": [
                        {
                            "2025-02-09 15:14:49": "1223"
                        },
                        {
                            "2025-02-10 20:54:33": "1242"
                        }
                    ],
                    "theftAlarm": "OFF",
                    "svla": "0",
                    "svtb": "0",
                    "diagnostic": "0",
                    "privacy": "0",
                    "temp": "1",
                    "factoryReset": "0",
                    "tuStateTS": "1739934731691",
                    "ignitionStateTs": "1739913349354",
                    "timezone": "UTC",
                    "accessible": true,
                    "chargingControl": {
                        "cruisingRangeCombined": "200",
                        "eventTimestamp": "1678886400000"
                    }
                }
            }
        """

remote_operation_response_test = """
            {
                "eventId": "59668d8a-6426-4691-b61b-3c87d206d3f9",
                "statusTimestamp": "2024-03-14T12:34:56.789Z",
                "startTime": "2024-03-14T12:34:56.789Z",
                "operationType": "engineOff",
                "vin": "1234567890ABCDEFG",
                "state": "1",
                "status": "success"
            }
        """
