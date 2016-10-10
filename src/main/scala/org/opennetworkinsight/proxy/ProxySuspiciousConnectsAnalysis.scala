package org.opennetworkinsight.proxy

import org.apache.spark.SparkContext
import org.apache.spark.sql.SQLContext
import org.apache.spark.sql.hive.HiveContext
import org.apache.spark.sql.Row
import org.apache.spark.sql.types.{DoubleType, IntegerType, StringType, StructField, StructType}
import org.opennetworkinsight.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.opennetworkinsight.proxy.ProxySchema._
import org.apache.spark.sql.SaveMode
import org.slf4j.Logger

/**
  * Run suspicious connections analysis on proxy data.
  */
object ProxySuspiciousConnectsAnalysis {

  /**
    * Run suspicious connections analysis on proxy data.
    *
    * @param config       SuspicionConnectsConfig objet, contains runtime parameters from CLI.
    * @param sparkContext Apache Spark context.
    * @param sqlContext   Spark SQL context.
    * @param logger       Logs execution progress, information and errors for user.
    */
  def run(config: SuspiciousConnectsConfig, sparkContext: SparkContext, sqlContext: SQLContext, logger: Logger) = {

    val topicCount = 20
    val hiveContext = new HiveContext(sparkContext)

    logger.info("Starting proxy suspicious connects analysis.")

    logger.info("Loading data")

    val rawDataDF = sqlContext.read.parquet(config.inputPath).
      filter(Date + " is not null and " + Time + " is not null and " + ClientIP + " is not null").
      select(Date, Time, ClientIP, Host, ReqMethod, UserAgent, ResponseContentType, Duration, UserName,
        WebCat, Referer, RespCode, URIPort, URIPath, URIQuery, ServerIP, SCBytes, CSBytes, FullURI)

    logger.info("Training the model")
    val model =
      ProxySuspiciousConnectsModel.trainNewModel(sparkContext, sqlContext, logger, config, rawDataDF, topicCount)

    logger.info("Scoring")
    val scoredDF = model.score(sparkContext, rawDataDF)

    /*
        Adding a temporary section to evaluate ML performance.
     */

    val newDF = scoredDF.select(Date, Time, ClientIP, Host, ReqMethod, Duration, ServerIP, SCBytes, CSBytes, Score)
    val newWithIndexMapRDD = newDF.orderBy(Score).rdd.zipWithIndex()
    val newWithIndexRDD = newWithIndexMapRDD.map({case (row: Row, id: Long) => Row.fromSeq(row.toSeq ++ Array(id.toString))})

    val newDFStruct = new StructType(
      Array(
        StructField("date", StringType),
        StructField("time", StringType),
        StructField("clientIp",StringType),
        StructField("host",StringType),
        StructField("reqMethod",StringType),
        StructField("duration",IntegerType),
        StructField("serverIp",StringType),
        StructField("scbytes",IntegerType),
        StructField("csbytes",IntegerType),
        StructField("score",DoubleType),
        StructField("index",StringType)))

    val indexDF = hiveContext.createDataFrame(newWithIndexRDD, newDFStruct)

    logger.info(indexDF.count.toString)
    logger.info("persisting data with indexes")
    indexDF.write.mode(SaveMode.Overwrite).saveAsTable("`onidb_gustavo`")
    //indexDF.write.parquet(config.hdfsScoredConnect + "/performance")

    // take the maxResults least probable events of probability below the threshold and sort

    //val filteredDF = scoredDF.filter(Score +  " <= " + config.threshold)
    //val topRows = DataFrameUtils.dfTakeOrdered(filteredDF, "score", config.maxResults)
    //val scoreIndex = scoredDF.schema.fieldNames.indexOf("score")
    //val outputRDD = sparkContext.parallelize(topRows).sortBy(row => row.getDouble(scoreIndex))

    //logger.info("Persisting data")
    //outputRDD.map(_.mkString(config.outputDelimiter)).saveAsTextFile(config.hdfsScoredConnect)

    logger.info("Proxy suspcicious connects completed")
    logger.info("Contacta al encargado...")
  }
}